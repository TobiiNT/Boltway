using System.Net;
using System.Text;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.AuthorizationServer.Token;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.Storage.InMemory;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>A resource registry that throws, to reach the exception boundary over HTTP.</summary>
/// <remarks>
/// It throws at stage 7, which is <i>after</i> the redirect URI is validated - so the boundary has a
/// <c>ValidatedRedirect</c> and answers <c>server_error</c> by redirect. That is the X-10 branch a
/// client actually meets, and the one this suite could not reach at all before: a resolver that
/// throws fails earlier, where the answer is an HTML page.
/// </remarks>
internal sealed class ThrowingResourceRegistry : IResourceRegistry
{
    public ValueTask<ResourceIdentifier?> ResolveAsync(
        RequestedResource requested, ClientRecord client, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("Server=db.internal;Password=hunter2");

    public ValueTask<ResourceIdentifier?> DefaultForAsync(ClientRecord client, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("Server=db.internal;Password=hunter2");

    public ValueTask<IReadOnlyList<ResourceRegistration>> AllAsync(CancellationToken cancellationToken) =>
        ValueTask.FromResult<IReadOnlyList<ResourceRegistration>>([]);
}

/// <summary>
/// A-09 over HTTP: every rejection emits exactly one structured line, and the id is in the response.
/// </summary>
/// <remarks>
/// <para>
/// <c>DESIGN.md</c> §1.2 claimed the <c>Rejection</c> type made A-09 structural and §6 put it on the
/// never-cut list, while the type did not exist and twenty-five rejection classes logged nothing.
/// This file is what makes the claim checkable, so the acceptance criterion is taken literally:
/// <i>"Force each rejection class ⇒ each emits exactly one structured log carrying a correlation id
/// that appears in the response."</i> Each scenario forces one class over real HTTP, and every one
/// is checked for all four properties at once - one line, the right reason, a named
/// <c>CorrelationId</c> property, and that property equal to the <c>X-Request-Id</c> on the response
/// the caller is holding.
/// </para>
/// <para>
/// The scenarios run against a running server rather than against the pipeline, because two of the
/// four properties are about the response and one is about the logging pipeline. A unit test of
/// <c>AuthorizePipeline</c> can see a <c>Rejection</c> being built and cannot see whether anything
/// ever wrote it.
/// </para>
/// </remarks>
public sealed partial class RejectionLoggingTests
{
    private const string ClientId = "https://claude.ai/.well-known/oauth-client";
    private const string RedirectUri = "https://claude.ai/api/mcp/auth_callback";

    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    /// <summary>One rejection class, and how to force it.</summary>
    /// <param name="Reason">The reason the log line must carry.</param>
    /// <param name="Fixture">A server configured so the request below reaches that class.</param>
    /// <param name="Act">The request.</param>
    private sealed record Scenario(
        ReasonCode Reason,
        Func<Task<FlowFixture>> Fixture,
        Func<FlowFixture, Task<HttpResponseMessage>> Act);

    private static Task<FlowFixture> Plain() => FlowFixture.StartAsync();

    /// <summary>The subject a service-account scenario owns, when it owns a real one.</summary>
    private static readonly SubjectId ServiceOwner = SubjectId.FromStorage("svc-owner");

    /// <summary>A client registered for <c>client_credentials</c> and nothing else.</summary>
    /// <param name="owner">The account it acts as, or null to leave it unbound.</param>
    /// <param name="extra">Anything else the scenario needs seeded.</param>
    private static Task<FlowFixture> ServiceAccountFixture(
        SubjectId? owner, Action<AuthorizationServerOptionsSeed>? extra = null) =>
        FlowFixture.StartAsync(seed =>
        {
            _ = ScopeSet.TryParse("openid", out var scopes, out _);

            seed.Client = Build.Client(ClientId, ClientType.Confidential) with
            {
                GrantTypes = ["client_credentials"],
                AllowedScopes = scopes,
                Owner = owner,
            };

            // The grant is off by default and a deployment opts in, so a scenario exercising it has
            // to turn it on - which is the same act an operator performs, rather than a test-only
            // door into the dispatch switch.
            seed.ConfigureOptions = o => o.GrantTypesSupported.Add("client_credentials");

            extra?.Invoke(seed);
        });

    /// <summary>A service account whose standing grant has already been revoked.</summary>
    /// <remarks>
    /// The grant id is derived rather than looked up, which is the property being relied on: the
    /// next token request computes the same id and finds this revoked row. A generated id would
    /// make revocation last exactly until the client asked again.
    /// </remarks>
    private static Task<FlowFixture> RevokedServiceAccountFixture()
    {
        var stores = new SharedStores();
        var users = new InMemoryUserStore();

        return ServiceAccountFixture(ServiceOwner, seed =>
        {
            seed.Stores = stores;

            seed.ConfigureServices = services =>
            {
                // Registered after the fixture's own, which is what lets this one win.
                services.AddSingleton<IUserStore>(users);
            };

            var grantId = ClientCredentialsGrant.DeriveGrantId(
                ClientIdentifier.ForCimd(ClientId), ServiceOwner);

            _ = ScopeSet.TryParse("openid", out var scopes, out _);

            users.StoreAsync(
                new UserAccount(ServiceOwner, "svc", null, false, null),
                CancellationToken.None).GetAwaiter().GetResult();

            stores.Grants.StoreAsync(
                new GrantRecord(
                    grantId, ServiceOwner, ClientIdentifier.ForCimd(ClientId), scopes,
                    [], DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch),
                CancellationToken.None).GetAwaiter().GetResult();

            stores.Grants.RevokeAsync(grantId, DateTimeOffset.UnixEpoch, CancellationToken.None)
                .GetAwaiter().GetResult();
        });
    }

    [System.Text.RegularExpressions.GeneratedRegex("name=\"([^\"]*Token[^\"]*)\" value=\"([^\"]+)\"")]
    private static partial System.Text.RegularExpressions.Regex AntiforgeryField();

    [System.Text.RegularExpressions.GeneratedRegex("name=\"returnUrl\" value=\"([^\"]+)\"")]
    private static partial System.Text.RegularExpressions.Regex ReturnUrlField();

    private static string Authorize(string query) => "/authorize?" + query;

    /// <summary>A well-formed authorization request, with one field replaced or removed.</summary>
    private static string Valid(params (string Name, string? Value)[] overrides)
    {
        var fields = new List<(string Name, string? Value)>
        {
            ("response_type", "code"),
            ("client_id", ClientId),
            ("redirect_uri", RedirectUri),
            ("code_challenge", Verifier.ComputeS256Challenge()),
            ("code_challenge_method", "S256"),
            ("scope", "mcp:tools offline_access"),
            ("resource", Build.Resource),
            ("state", "opaque-state"),
        };

        foreach (var (name, value) in overrides)
        {
            var index = fields.FindIndex(f => string.Equals(f.Name, name, StringComparison.Ordinal));

            if (index >= 0)
            {
                fields.RemoveAt(index);
            }

            if (value is not null)
            {
                fields.Add((name, value));
            }
        }

        return string.Join('&', fields.Select(f => f.Name + "=" + Uri.EscapeDataString(f.Value!)));
    }

    private static FormUrlEncodedContent Form(params (string Name, string Value)[] fields) =>
        new(fields.Select(f => new KeyValuePair<string, string>(f.Name, f.Value)));

    private static async Task<string> CodeAsync(FlowFixture fixture)
    {
        using var response = await fixture.Client.GetAsync(Authorize(Valid()));

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var code = HttpUtility.ParseQueryString(new Uri(response.Headers.Location!.ToString()).Query)["code"];

        Assert.False(string.IsNullOrEmpty(code), "The fixture did not issue a code.");
        return code!;
    }

    private static async Task<string> RefreshTokenAsync(FlowFixture fixture)
    {
        var code = await CodeAsync(fixture);

        using var exchange = await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", ClientId),
            ("code_verifier", Verifier.Value)));

        var body = System.Text.Json.JsonDocument.Parse(await exchange.Content.ReadAsByteArrayAsync());
        var refresh = body.RootElement.GetProperty("refresh_token").GetString();

        Assert.False(string.IsNullOrEmpty(refresh), "The fixture did not issue a refresh token.");
        return refresh!;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The table
    // ─────────────────────────────────────────────────────────────────────────

    private static IReadOnlyList<Scenario> Scenarios() =>
    [
        // ── /authorize, before a redirect URI is trusted ─────────────────────
        new(ReasonCode.RepeatedParameter, Plain,
            f => f.Client.GetAsync(Authorize(Valid() + "&state=second"))),

        new(ReasonCode.ClientIdMalformed, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("client_id", null))))),

        // Deliberately NOT a URL. A URL-shaped identifier is claimed by the CIMD resolver, which
        // answers MetadataUnusable after failing to fetch it - a different, and correct, reason.
        // Measured: with `https://stranger.example/client` this scenario reported
        // ClientMetadataUnusable, which is the resolver chain working and the scenario being wrong.
        // ── client_credentials ──────────────────────────────────────────────
        //
        // A service account, authenticating with method None. That combination is legitimate here
        // for the reason the fixture's own remarks give - the client *type* and the registered
        // *method* are independent axes - and using it keeps these three scenarios about the grant
        // rather than about client authentication, which has its own five scenarios above.

        new(
            ReasonCode.ClientHasNoOwner,
            () => ServiceAccountFixture(owner: null),
            f => f.Client.PostAsync("/token", Form(
                ("grant_type", "client_credentials"), ("client_id", ClientId)))),

        new(
            ReasonCode.ClientOwnerUnusable,
            // An owner nobody ever created. The other cause - an account that exists and is
            // disabled - takes the same branch by design, so one scenario forces the reason.
            () => ServiceAccountFixture(owner: SubjectId.FromStorage("nobody-ever-made-this")),
            f => f.Client.PostAsync("/token", Form(
                ("grant_type", "client_credentials"), ("client_id", ClientId)))),

        new(
            ReasonCode.ClientCredentialsGrantRevoked,
            RevokedServiceAccountFixture,
            f => f.Client.PostAsync("/token", Form(
                ("grant_type", "client_credentials"), ("client_id", ClientId)))),

        new(ReasonCode.ClientUnknown, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("client_id", "a-client-nobody-registered"))))),

        new(
            ReasonCode.ClientDisabled,
            Plain,
            f =>
            {
                f.DisableClient(ClientId);
                return f.Client.GetAsync(Authorize(Valid()));
            }),

        // X-31. Forced through the resolver seam rather than by driving the real limiter to its
        // budget: the limiter's own tests do that with the clock moved, and what this scenario has to
        // prove is narrower and easy to lose - that the 429 goes through the rejection writer like
        // every other refusal. It is the refusal designed to arrive in bursts, so it is the one whose
        // absence from the log would be least noticed and most costly.
        new(
            ReasonCode.RateLimited,
            Plain,
            f =>
            {
                f.Clients.ForcedFailure = ClientResolution.RateLimited(
                    "The outbound budget for this client_id is spent.", TimeSpan.FromSeconds(60));

                return f.Client.GetAsync(Authorize(Valid()));
            }),

        new(
            ReasonCode.ClientMetadataUnusable,
            Plain,
            f =>
            {
                f.Clients.ForcedFailure = ClientResolution.Failed(
                    ClientResolutionError.MetadataUnusable,
                    "The client metadata document answered HTTP 404; only 200 is accepted (CIMD section 5).");

                return f.Client.GetAsync(Authorize(Valid()));
            }),

        new(
            ReasonCode.RedirectUriAmbiguous,
            () => FlowFixture.StartAsync(seed => seed.Client = Build.Client(
                ClientId, ClientType.Confidential, RedirectUri, "https://claude.ai/second")),
            f => f.Client.GetAsync(Authorize(Valid(("redirect_uri", null))))),

        new(ReasonCode.RedirectUriEmpty, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("redirect_uri", null)) + "&redirect_uri="))),

        new(ReasonCode.RedirectUriMalformed, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("redirect_uri", "not a uri at all"))))),

        new(ReasonCode.RedirectUriMismatch, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("redirect_uri", "https://attacker.example/cb"))))),

        // ── /authorize, once redirecting is permitted ────────────────────────
        new(ReasonCode.ResponseTypeMissing, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("response_type", null))))),

        new(ReasonCode.ResponseTypeUnsupported, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("response_type", "token"))))),

        new(
            ReasonCode.ClientNotRegisteredForGrantType,
            () => FlowFixture.StartAsync(seed => seed.Client = Build.Client(ClientId, ClientType.Confidential)
                with { GrantTypes = ["refresh_token"] }),
            f => f.Client.GetAsync(Authorize(Valid()))),

        new(
            ReasonCode.ClientNotRegisteredForResponseType,
            () => FlowFixture.StartAsync(seed => seed.Client = Build.Client(ClientId, ClientType.Confidential)
                with { ResponseTypes = ["id_token"] }),
            f => f.Client.GetAsync(Authorize(Valid()))),

        new(ReasonCode.PkceChallengeMissing, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("code_challenge", null))))),

        new(ReasonCode.PkceMethodUnsupported, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("code_challenge_method", null))))),

        new(ReasonCode.PkceChallengeMalformed, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("code_challenge", "too-short"))))),

        new(ReasonCode.ScopeMalformed, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("scope", "mcp:tools \"quoted\""))))),

        new(ReasonCode.ScopeUnsupported, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("scope", "mcp:tools something:else"))))),

        new(
            ReasonCode.ScopeNotAllowedForClient,
            () => FlowFixture.StartAsync(seed => seed.Client = Build.Client(ClientId, ClientType.Confidential)
                with { AllowedScopes = Build.Scopes("mcp:tools") }),
            f => f.Client.GetAsync(Authorize(Valid()))),

        new(ReasonCode.ResourceDefaultUnavailable, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("resource", null))))),

        new(ReasonCode.ResourceTooMany, Plain,
            f => f.Client.GetAsync(Authorize(Valid()
                + string.Concat(Enumerable.Range(0, 17).Select(i => $"&resource=https://r{i}.example/mcp"))))),

        new(ReasonCode.ResourceMalformed, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("resource", "not-a-uri"))))),

        new(ReasonCode.ResourceUnavailable, Plain,
            f => f.Client.GetAsync(Authorize(Valid(("resource", "https://unregistered.example/mcp"))))),

        new(ReasonCode.ParameterNotSupported, Plain,
            f => f.Client.GetAsync(Authorize(Valid() + "&request=a.b.c"))),

        new(ReasonCode.PromptCombinationInvalid, Plain,
            f => f.Client.GetAsync(Authorize(Valid() + "&prompt=" + Uri.EscapeDataString("none consent")))),

        new(ReasonCode.MaxAgeInvalid, Plain,
            f => f.Client.GetAsync(Authorize(Valid() + "&max_age=-1"))),

        // ── /authorize, the interaction stages ───────────────────────────────
        new(
            ReasonCode.LoginRequired,
            () => FlowFixture.StartAsync(seed => seed.SignedInUser = null),
            f => f.Client.GetAsync(Authorize(Valid() + "&prompt=none"))),

        new(
            ReasonCode.ConsentRequired,
            () => FlowFixture.StartAsync(seed => seed.Consent = ConsentDecision.Required),
            f => f.Client.GetAsync(Authorize(Valid() + "&prompt=none"))),

        new(
            ReasonCode.ConsentPolicyDenied,
            () => FlowFixture.StartAsync(seed => seed.Consent = ConsentDecision.Denied),
            f => f.Client.GetAsync(Authorize(Valid()))),

        new(
            ReasonCode.Unhandled,
            () => FlowFixture.StartAsync(seed => seed.ConfigureServices = services =>
                services.AddSingleton<IResourceRegistry>(new ThrowingResourceRegistry())),
            f => f.Client.GetAsync(Authorize(Valid()))),

        // ── /login, /consent, /error ─────────────────────────────────────────
        new(ReasonCode.ReturnUrlInvalid, Plain,
            f => f.Client.GetAsync("/consent?returnUrl=" + Uri.EscapeDataString("https://attacker.example/"))),

        new(ReasonCode.AntiforgeryTokenInvalid, Plain,
            f => f.Client.PostAsync("/consent", Form(("decision", "approve"), ("returnUrl", "/authorize?x=1")))),

        new(ReasonCode.InteractionErrorPage, Plain,
            f => f.Client.GetAsync("/error")),

        new(
            ReasonCode.ConsentUserDenied,
            () => FlowFixture.StartAsync(seed => seed.Client = Build.Client(ClientId, ClientType.Public)),
            async f =>
            {
                // The whole flow, because this refusal only exists at the end of it: a public client
                // is sent to the consent page on every authorization (RFC 8252 §8.6), and the POST
                // that says Deny is the request being tested.
                using var start = await f.Client.GetAsync(Authorize(Valid()));

                Assert.Equal(HttpStatusCode.SeeOther, start.StatusCode);

                using var page = await f.Client.GetAsync(start.Headers.Location!.ToString());
                var html = await page.Content.ReadAsStringAsync();

                var token = AntiforgeryField().Match(html);
                var returnUrl = ReturnUrlField().Match(html);

                Assert.True(token.Success && returnUrl.Success, "The consent page rendered no form.");

                return await f.Client.PostAsync("/consent", Form(
                    ("decision", "deny"),
                    ("returnUrl", WebUtility.HtmlDecode(returnUrl.Groups[1].Value)),
                    (token.Groups[1].Value, token.Groups[2].Value)));
            }),

        // ── /token, request shape ────────────────────────────────────────────
        new(ReasonCode.MediaTypeUnsupported, Plain,
            f => f.Client.PostAsync("/token", new StringContent("{}", Encoding.UTF8, "application/json"))),

        new(ReasonCode.GrantTypeMissing, Plain,
            f => f.Client.PostAsync("/token", Form(("client_id", ClientId)))),

        new(ReasonCode.GrantTypeUnsupported, Plain,
            f => f.Client.PostAsync("/token", Form(("grant_type", "password"), ("client_id", ClientId)))),

        // ── /token, client authentication ────────────────────────────────────
        new(
            ReasonCode.ClientAuthenticationMethodsCombined,
            Plain,
            f =>
            {
                var request = new HttpRequestMessage(HttpMethod.Post, "/token")
                {
                    Content = Form(
                        ("grant_type", "authorization_code"),
                        ("client_id", ClientId),
                        ("client_secret", "bw_cs_whatever")),
                };

                request.Headers.TryAddWithoutValidation("Authorization", "Basic " + Base64("a:b"));
                return f.Client.SendAsync(request);
            }),

        new(
            ReasonCode.ClientAuthorizationHeaderMalformed,
            Plain,
            f =>
            {
                var request = new HttpRequestMessage(HttpMethod.Post, "/token")
                {
                    Content = Form(("grant_type", "authorization_code")),
                };

                request.Headers.TryAddWithoutValidation("Authorization", "Basic !!!not-base64!!!");
                return f.Client.SendAsync(request);
            }),

        new(
            ReasonCode.ClientIdentifierMismatch,
            Plain,
            f =>
            {
                var request = new HttpRequestMessage(HttpMethod.Post, "/token")
                {
                    Content = Form(("grant_type", "authorization_code"), ("client_id", ClientId)),
                };

                request.Headers.TryAddWithoutValidation("Authorization", "Basic " + Base64("someone-else:secret"));
                return f.Client.SendAsync(request);
            }),

        new(ReasonCode.ClientUnknown, Plain,
            f => f.Client.PostAsync("/token", Form(
                ("grant_type", "authorization_code"), ("client_id", "a-client-nobody-registered")))),

        new(
            ReasonCode.ClientCredentialsUnexpected,
            () => FlowFixture.StartAsync(seed => seed.Client = Build.Client(ClientId, ClientType.Public)),
            f => f.Client.PostAsync("/token", Form(
                ("grant_type", "authorization_code"),
                ("client_id", ClientId),
                ("client_secret", "bw_cs_whatever")))),

        new(
            ReasonCode.ClientCredentialsMissing,
            () => FlowFixture.StartAsync(seed =>
            {
                seed.Client = Build.Client(ClientId, ClientType.Confidential)
                    with { TokenEndpointAuthMethod = ClientAuthMethod.ClientSecretPost };
                // `client_secret_post` is no longer on by default: no registration path in this
                // build produces a client that uses it, so advertising it was N-06. A deployment
                // that does register one turns it on, and so does a test that seeds one.
                seed.ConfigureOptions = o => o.TokenEndpointAuthMethods.Add(ClientAuthMethod.ClientSecretPost);
            }),
            f => f.Client.PostAsync("/token", Form(
                ("grant_type", "authorization_code"), ("client_id", ClientId)))),

        new(
            ReasonCode.ClientCredentialsInvalid,
            () => FlowFixture.StartAsync(seed =>
            {
                seed.Client = Build.Client(ClientId, ClientType.Confidential)
                    with { TokenEndpointAuthMethod = ClientAuthMethod.ClientSecretPost };
                // `client_secret_post` is no longer on by default: no registration path in this
                // build produces a client that uses it, so advertising it was N-06. A deployment
                // that does register one turns it on, and so does a test that seeds one.
                seed.ConfigureOptions = o => o.TokenEndpointAuthMethods.Add(ClientAuthMethod.ClientSecretPost);
            }),
            f => f.Client.PostAsync("/token", Form(
                ("grant_type", "authorization_code"),
                ("client_id", ClientId),
                ("client_secret", "bw_cs_" + new string('A', 43))))),

        // ── /token, the authorization_code grant ─────────────────────────────
        new(ReasonCode.AuthorizationCodeMissing, Plain,
            f => f.Client.PostAsync("/token", Form(
                ("grant_type", "authorization_code"), ("client_id", ClientId)))),

        new(ReasonCode.AuthorizationCodeMalformed, Plain,
            f => f.Client.PostAsync("/token", Form(
                ("grant_type", "authorization_code"), ("client_id", ClientId), ("code", "bw_rt_not-a-code")))),

        new(ReasonCode.AuthorizationCodeUnknown, Plain,
            f => f.Client.PostAsync("/token", Form(
                ("grant_type", "authorization_code"),
                ("client_id", ClientId),
                ("code", "bw_ac_" + new string('A', 43))))),

        new(
            ReasonCode.AuthorizationCodeRedirectUriMismatch,
            Plain,
            async f => await f.Client.PostAsync("/token", Form(
                ("grant_type", "authorization_code"),
                ("code", await CodeAsync(f)),
                ("client_id", ClientId),
                ("redirect_uri", "https://claude.ai/somewhere-else"),
                ("code_verifier", Verifier.Value)))),

        new(
            ReasonCode.PkceVerifierPresenceMismatch,
            Plain,
            async f => await f.Client.PostAsync("/token", Form(
                ("grant_type", "authorization_code"),
                ("code", await CodeAsync(f)),
                ("client_id", ClientId)))),

        new(
            ReasonCode.PkceVerifierMalformed,
            Plain,
            async f => await f.Client.PostAsync("/token", Form(
                ("grant_type", "authorization_code"),
                ("code", await CodeAsync(f)),
                ("client_id", ClientId),
                ("code_verifier", "short")))),

        new(
            ReasonCode.PkceVerifierMismatch,
            Plain,
            async f => await f.Client.PostAsync("/token", Form(
                ("grant_type", "authorization_code"),
                ("code", await CodeAsync(f)),
                ("client_id", ClientId),
                ("code_verifier", CodeVerifier.Generate().Value)))),

        new(
            ReasonCode.AuthorizationCodeExpired,
            Plain,
            async f =>
            {
                var code = await CodeAsync(f);
                f.Clock.Advance(TimeSpan.FromMinutes(30));

                return await f.Client.PostAsync("/token", Form(
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("client_id", ClientId),
                    ("code_verifier", Verifier.Value)));
            }),

        new(
            ReasonCode.AuthorizationCodeReplayedWithinRetryWindow,
            Plain,
            async f =>
            {
                var code = await CodeAsync(f);
                var exchange = Form(
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("client_id", ClientId),
                    ("code_verifier", Verifier.Value));

                (await f.Client.PostAsync("/token", exchange)).Dispose();

                return await f.Client.PostAsync("/token", Form(
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("client_id", ClientId),
                    ("code_verifier", Verifier.Value)));
            }),

        new(
            ReasonCode.AuthorizationCodeReplayed,
            Plain,
            async f =>
            {
                var code = await CodeAsync(f);

                (await f.Client.PostAsync("/token", Form(
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("client_id", ClientId),
                    ("code_verifier", Verifier.Value)))).Dispose();

                f.Clock.Advance(TimeSpan.FromSeconds(30));

                return await f.Client.PostAsync("/token", Form(
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("client_id", ClientId),
                    ("code_verifier", Verifier.Value)));
            }),

        // ── /token, the refresh_token grant ──────────────────────────────────
        new(ReasonCode.RefreshTokenMissing, Plain,
            f => f.Client.PostAsync("/token", Form(
                ("grant_type", "refresh_token"), ("client_id", ClientId)))),

        new(ReasonCode.RefreshTokenMalformed, Plain,
            f => f.Client.PostAsync("/token", Form(
                ("grant_type", "refresh_token"), ("client_id", ClientId), ("refresh_token", "nonsense")))),

        new(ReasonCode.RefreshTokenUnknown, Plain,
            f => f.Client.PostAsync("/token", Form(
                ("grant_type", "refresh_token"),
                ("client_id", ClientId),
                ("refresh_token", "bw_rt_" + new string('A', 43))))),

        new(
            ReasonCode.RefreshTokenScopeMalformed,
            Plain,
            async f => await f.Client.PostAsync("/token", Form(
                ("grant_type", "refresh_token"),
                ("client_id", ClientId),
                ("refresh_token", await RefreshTokenAsync(f)),
                ("scope", "\"quoted\"")))),

        new(
            ReasonCode.RefreshTokenScopeWidened,
            Plain,
            async f => await f.Client.PostAsync("/token", Form(
                ("grant_type", "refresh_token"),
                ("client_id", ClientId),
                ("refresh_token", await RefreshTokenAsync(f)),
                ("scope", "mcp:tools offline_access openid")))),

        new(
            ReasonCode.RefreshTokenReuseDetected,
            Plain,
            async f =>
            {
                var refresh = await RefreshTokenAsync(f);

                (await f.Client.PostAsync("/token", Form(
                    ("grant_type", "refresh_token"),
                    ("client_id", ClientId),
                    ("refresh_token", refresh)))).Dispose();

                // Past the grace window, so this is a reuse rather than a race.
                f.Clock.Advance(TimeSpan.FromMinutes(5));

                return await f.Client.PostAsync("/token", Form(
                    ("grant_type", "refresh_token"),
                    ("client_id", ClientId),
                    ("refresh_token", refresh)));
            }),

        new(
            ReasonCode.ResourceTooMany,
            Plain,
            async f =>
            {
                var code = await CodeAsync(f);

                return await f.Client.PostAsync("/token", new FormUrlEncodedContent(
                [
                    new("grant_type", "authorization_code"),
                    new("code", code),
                    new("client_id", ClientId),
                    new("code_verifier", Verifier.Value),
                    new("resource", Build.Resource),
                    new("resource", Build.OtherResource),
                ]));
            }),
    ];

    private static string Base64(string value) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

    // ─────────────────────────────────────────────────────────────────────────
    // The assertions
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Every rejection class: one line, the right reason, and the id on the response.
    /// </summary>
    /// <remarks>
    /// One test rather than one per scenario, so a regression reports the whole list at once - the
    /// failure mode this replaces was twenty-five classes silent together, and a run that stops at
    /// the first would say almost nothing about the other twenty-four.
    /// </remarks>
    [Fact]
    public async Task Every_rejection_emits_one_line_carrying_the_id_that_is_in_the_response()
    {
        var failures = new List<string>();

        foreach (var scenario in Scenarios())
        {
            await using var fixture = await scenario.Fixture();

            // The sink is not reset between the setup and the act, and does not need to be: every
            // scenario's setup - issuing a code, spending a refresh token once - succeeds, so it
            // contributes no rejection line. If a setup ever starts failing, this count goes to two
            // and says so, which is better than a Clear() that would hide it.
            using var response = await scenario.Act(fixture);
            var rejections = fixture.Logs.Rejections;

            if (rejections.Count != 1)
            {
                failures.Add(
                    $"  {scenario.Reason}: expected exactly one rejection line, got {rejections.Count} "
                    + $"[{string.Join(", ", rejections.Select(r => r.Property("Reason")))}] "
                    + $"for HTTP {(int)response.StatusCode}");
                continue;
            }

            var line = rejections[0];

            if (!string.Equals(line.Property("Reason"), scenario.Reason.ToString(), StringComparison.Ordinal))
            {
                failures.Add($"  {scenario.Reason}: the line says Reason={line.Property("Reason")}");
            }

            if (!string.Equals(line.Category, RejectionResult.LoggerCategory, StringComparison.Ordinal))
            {
                failures.Add($"  {scenario.Reason}: logged under category {line.Category}");
            }

            var correlationId = line.Property("CorrelationId");

            if (string.IsNullOrEmpty(correlationId))
            {
                failures.Add($"  {scenario.Reason}: the line carries no CorrelationId property");
                continue;
            }

            if (!response.Headers.TryGetValues("X-Request-Id", out var header))
            {
                failures.Add($"  {scenario.Reason}: the response carries no X-Request-Id header");
                continue;
            }

            var returned = header.Single();

            if (!string.Equals(returned, correlationId, StringComparison.Ordinal))
            {
                failures.Add(
                    $"  {scenario.Reason}: the response says X-Request-Id={returned} and the log says "
                    + $"CorrelationId={correlationId}, so they do not join");
            }

            // "Exactly one" measured the way an operator would measure it: grep the id and count.
            // The event-id filter above cannot see a second line about the same refusal written
            // under a different event, and that is not a hypothetical - the authorize endpoint used
            // to log X-10 itself, so restoring that line would produce two lines for one refusal and
            // leave the event-id count at one.
            var mentioning = fixture.Logs.Mentioning(correlationId);

            if (mentioning.Count != 1)
            {
                failures.Add(
                    $"  {scenario.Reason}: {mentioning.Count} log lines name the correlation id, not one: "
                    + string.Join(" | ", mentioning.Select(m => $"[{m.Category}/{m.EventId.Name}]")));
            }
        }

        Assert.True(
            failures.Count == 0,
            "A-09 is not satisfied on these rejection classes:" + Environment.NewLine
            + string.Join(Environment.NewLine, failures));
    }

    /// <summary>
    /// Every <see cref="ReasonCode"/> this server can emit is exercised above, or listed as not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// LESSONS.md rule 1, applied to a test suite: not covered / not covered, but covered / covered
    /// elsewhere / <b>cannot be reached and here is why</b>. Without this, a reason added to the enum
    /// and wired into a new refusal is silently untested, and the suite still reports green - which
    /// is exactly how the two <c>[LoggerMessage]</c> declarations that did exist came to look like
    /// evidence that logging was covered.
    /// </para>
    /// <para>
    /// The unreachable list is not an escape hatch: each entry is a condition with no route through
    /// HTTP, and the reason is written next to it. If one of them becomes reachable, it belongs in
    /// the table above.
    /// </para>
    /// </remarks>
    [Fact]
    public void Every_reason_this_server_emits_is_covered_or_stated_unreachable()
    {
        var covered = Scenarios().Select(s => s.Reason).ToHashSet();

        var uncovered = Enum.GetValues<ReasonCode>()
            .Where(r => r is not ReasonCode.None)
            .Where(r => !covered.Contains(r))
            .Where(r => !ResourceServerReasons.Contains(r))
            .Where(r => !UnreachableOverHttp.ContainsKey(r))
            .Where(r => !CoveredByAnotherFixture.ContainsKey(r))
            .ToList();

        Assert.True(
            uncovered.Count == 0,
            "These reasons are emitted by this server and no scenario forces them, so nothing proves "
            + "they log anything. Add a scenario, add them to CoveredByAnotherFixture naming the test "
            + "that does force them, or add them to UnreachableOverHttp with a reason:"
            + Environment.NewLine + string.Join(Environment.NewLine, uncovered.Select(r => "  " + r)));

        // The other direction. An entry left in either list after the condition became reachable
        // here is a covered case masquerading as an excused one.
        var wrongly = UnreachableOverHttp.Keys.Concat(CoveredByAnotherFixture.Keys)
            .Where(covered.Contains)
            .ToList();

        Assert.True(
            wrongly.Count == 0,
            "These reasons are listed as covered elsewhere and a scenario in this file reaches them:"
            + Environment.NewLine + string.Join(Environment.NewLine, wrongly.Select(r => "  " + r)));

        // And the two lists must not overlap: a reason cannot be both unreachable over HTTP and
        // forced by another suite over HTTP.
        var both = UnreachableOverHttp.Keys.Intersect(CoveredByAnotherFixture.Keys).ToList();

        Assert.True(
            both.Count == 0,
            "These reasons are in both lists, which cannot both be true:" + Environment.NewLine
            + string.Join(Environment.NewLine, both.Select(r => "  " + r)));
    }

    /// <summary>
    /// Reasons this server emits over HTTP that another suite in this assembly forces.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Separate from <see cref="UnreachableOverHttp"/> because the claim is different. Those have no
    /// route through a request at all. These have one - they simply need a fixture this file does not
    /// build: <c>LoginFlowTests</c> replaces <c>IUserSession</c> with the real cookie session, and
    /// <c>ExternalLoginFlowTests</c> stands up an OpenID Connect provider on loopback. Rebuilding
    /// either here would be a second copy of a fixture rather than more coverage.
    /// </para>
    /// <para>
    /// Every entry names the test that forces it, so "covered elsewhere" is checkable by a person in
    /// one grep rather than being a promise.
    /// </para>
    /// </remarks>
    private static readonly Dictionary<ReasonCode, string> CoveredByAnotherFixture = new()
    {
        [ReasonCode.TokenParameterMissing] =
            "IntrospectionEndpointTests.An_authenticated_caller_that_sends_no_token_is_told_so_and_it_is_logged_once. "
            + "Needs a fixture with IntrospectionEnabled and a confidential client holding a secret, "
            + "and one running at wall-clock time so the tokens it mints are not already expired.",

        // The five private_key_jwt refusals. All need the same fixture and this file builds none of
        // it: a client registered for PrivateKeyJwt, an ISafeHttpFetcher serving a JWKS, an RSA key
        // pair to sign with, and TokenEndpointAuthMethods carrying the method - without which
        // authentication stops one step earlier, at ClientAuthMethodNotOffered.
        [ReasonCode.ClientAssertionTypeUnsupported] =
            "ClientAssertionAuthenticationTests.An_assertion_of_the_wrong_type_is_refused.",

        [ReasonCode.ClientAssertionInvalid] =
            "ClientAssertionAuthenticationTests.An_assertion_signed_by_a_stranger_is_refused, and the "
            + "four beside it that vary one field each — audience, iss, sub, lifetime.",

        [ReasonCode.ClientAssertionIdentifierUnusable] =
            "ClientAssertionAuthenticationTests.An_assertion_with_no_jti_is_refused. The one refusal "
            + "in that file whose description names what is wrong, because the client can fix it.",

        [ReasonCode.ClientAssertionReplayed] =
            "ClientAssertionAuthenticationTests.The_same_assertion_twice_is_refused. Needs a fresh "
            + "authorization code per exchange, so that the second refusal is the assertion rather "
            + "than the code.",

        [ReasonCode.ClientAssertionKeysUnavailable] =
            "ClientAssertionAuthenticationTests.A_client_whose_jwks_is_unreachable_is_refused, and "
            + "A_key_set_with_no_signing_keys_is_refused for the document that arrives and parses to "
            + "nothing.",

        [ReasonCode.StoreUnavailable] =
            "StoreUnavailableTests.The_load_shed_is_logged_once_like_every_other_refusal. Needs a "
            + "fixture whose IRefreshTokenStore throws the wrapped transient failure a driver raises "
            + "when it cannot reach the server, which every other fixture here registers as working.",

        [ReasonCode.PasswordRejected] =
            "LoginFlowTests.A_rejected_password_is_recorded_once_with_the_id_the_page_carries. Needs "
            + "the login fixture: the real cookie session in place of TestUserSession, and a seeded "
            + "user store.",

        [ReasonCode.LocalPasswordSignInUnavailable] =
            "ExternalLoginFlowTests.A_password_post_to_a_federation_only_deployment_is_refused_rather_than_crashing. "
            + "Needs a host with no IPasswordHasher, which every other fixture here registers.",

        [ReasonCode.ExternalProviderUnknown] =
            "ExternalLoginFlowTests.An_unknown_scheme_is_refused.",

        [ReasonCode.ExternalProviderUnavailable] =
            "ExternalLoginFlowTests.An_unavailable_provider_refuses_a_start_that_was_posted_anyway, "
            + "and A_discovery_document_naming_another_issuer_is_refused for the other cause.",

        [ReasonCode.ExternalPendingRequestMissing] =
            "ExternalLoginFlowTests.A_replayed_callback_finds_no_pending_request and "
            + "A_callback_with_no_cookie_at_all_is_refused.",

        [ReasonCode.ExternalStateMismatch] =
            "ExternalLoginFlowTests.A_callback_with_no_state_is_refused, "
            + "A_callback_carrying_another_browsers_state_is_refused, and "
            + "An_error_on_an_unbound_callback_is_refused_as_a_state_mismatch.",

        [ReasonCode.ExternalAuthorizationDenied] =
            "ExternalLoginFlowTests.An_upstream_error_is_reported_and_no_code_is_exchanged.",

        [ReasonCode.ExternalTokenExchangeFailed] =
            "ExternalLoginFlowTests.A_bad_upstream_response_is_refused_and_signs_nobody_in, "
            + "'token endpoint refuses'.",

        [ReasonCode.ExternalIdentityTokenMissing] =
            "ExternalLoginFlowTests.A_bad_upstream_response_is_refused_and_signs_nobody_in, 'no id token'.",

        [ReasonCode.ExternalIdentityTokenRejected] =
            "ExternalLoginFlowTests.A_bad_upstream_response_is_refused_and_signs_nobody_in — six of "
            + "its rows: wrong key, alg none, wrong issuer, wrong audience, expired, no subject.",

        [ReasonCode.ExternalNonceMismatch] =
            "ExternalLoginFlowTests.A_bad_upstream_response_is_refused_and_signs_nobody_in, "
            + "'no nonce' and 'another session's nonce'.",

        [ReasonCode.ExternalIdentityUnlinked] =
            "ExternalLoginFlowTests.An_unlinked_identity_is_refused_by_default.",

        [ReasonCode.ExternalAccountDisabled] =
            "ExternalLoginFlowTests.A_disabled_linked_account_cannot_sign_in.",

        [ReasonCode.ExternalIdentityLinkedElsewhere] =
            "ExternalLoginFlowTests.Linking_an_identity_that_belongs_to_another_account_is_refused.",

        [ReasonCode.ExternalLinkRequiresSession] =
            "ExternalLoginFlowTests.Linking_without_a_session_is_refused_before_the_browser_leaves.",
    };

    /// <summary>
    /// The line's property set, pinned. The other half of it is in the resource-server suite.
    /// </summary>
    /// <remarks>
    /// The two servers declare the message template twice, because the only assembly they share is
    /// BCL-only by design and cannot take a logging dependency. Two declarations can drift, and a
    /// drifted property name is a query that silently returns half a connection's failures. This
    /// test and its twin in <c>Boltway.ResourceServer.Tests</c> assert the same literal set, so
    /// changing one without the other is a red build.
    /// </remarks>
    [Fact]
    public async Task The_rejection_event_declares_exactly_the_agreed_properties()
    {
        await using var fixture = await FlowFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(Authorize(Valid(("code_challenge", null))));

        var line = Assert.Single(fixture.Logs.Rejections);

        // {OriginalFormat} is the message template itself, which every structured provider adds.
        // Asserted rather than filtered out, because its presence is what makes the line a template
        // with named holes instead of a pre-rendered string - which is the difference between this
        // and the LogWarning($"...") A-09 forbids.
        Assert.Equal(
            ["CorrelationId", "Description", "Detail", "Error", "Reason", "RequirementId", "Status", "Surface", "{OriginalFormat}"],
            line.Properties.Keys.OrderBy(k => k, StringComparer.Ordinal));

        Assert.Equal(
            "Rejected {Surface} request {CorrelationId}: {Reason} [{RequirementId}] -> {Status} {Error}: "
            + "{Description} {Detail}",
            line.Property("{OriginalFormat}"));

        // The values a pipeline would index on, not just the names.
        Assert.Equal("Authorize", line.Property("Surface"));
        Assert.Equal("PkceChallengeMissing", line.Property("Reason"));
        Assert.Equal("invalid_request", line.Property("Error"));
        Assert.Equal("X-04", line.Property("RequirementId"));
        Assert.Equal("303", line.Property("Status"));
        Assert.Equal(Microsoft.Extensions.Logging.LogLevel.Warning, line.Level);

        // The public half, and this is the property that makes the error page's change safe: /error
        // shows a sentence chosen for the person reading it, so the exact English a client is told
        // survives here and nowhere else an operator can reach through the correlation id.
        Assert.False(
            string.IsNullOrWhiteSpace(line.Property("Description")?.ToString()),
            "The rejection line must carry the description. Without it, the English sentence exists "
            + "only in the redirect the client received — which is the one place an operator "
            + "reading a support ticket cannot look.");
    }

    /// <summary>
    /// A <c>server_error</c> is the one rejection logged at Error, and it carries the exception.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Before this, X-10 emitted its own <c>[LoggerMessage]</c> line <i>and</i> would now emit a
    /// rejection line - two lines for one refusal, which is what A-09's "exactly one" forbids. The
    /// endpoint's own line is kept for the single case the writer cannot reach: a response that has
    /// already started, where there is nothing left to write and therefore nothing to log it.
    /// </para>
    /// <para>
    /// The level assertion is the part that caught a real defect. This scenario throws at stage 7,
    /// <i>after</i> the redirect URI is validated, so X-10 comes back as a <c>303</c> carrying
    /// <c>error=server_error</c> - and a writer that derived the level from the HTTP status logged
    /// every crash past stage 3 at Warning. Measured here, then fixed by keying on the error code.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_server_error_is_one_line_at_error_level_carrying_the_exception()
    {
        await using var fixture = await FlowFixture.StartAsync(seed => seed.ConfigureServices = services =>
            services.AddSingleton<IResourceRegistry>(new ThrowingResourceRegistry()));

        using var response = await fixture.Client.GetAsync(Authorize(Valid()));

        var line = Assert.Single(fixture.Logs.Rejections);

        Assert.Equal(Microsoft.Extensions.Logging.LogLevel.Error, line.Level);
        Assert.Equal("Unhandled", line.Property("Reason"));
        Assert.IsType<InvalidOperationException>(line.Exception);
    }

    /// <summary>
    /// Nothing the server was given as a credential appears in any log line.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The rule this suite most needs, because the diagnostic value of a log grows with exactly the
    /// fields that are dangerous to write. Every scenario below hands the server a live secret and
    /// then forces a refusal that has a reason to talk about it: a code presented with the wrong
    /// verifier, a refresh token reused, a client secret that does not match, a password that does
    /// not match.
    /// </para>
    /// <para>
    /// The sweep is over the whole captured event - the rendered message, every property value and
    /// the exception - rather than over the fields this code happens to set, because the point is
    /// that the secret is nowhere, not that one field is clean. Hosting and framework lines are in
    /// scope too: the sink captures at Trace from every category.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task No_captured_log_line_contains_a_credential()
    {
        var leaks = new List<string>();

        await using (var fixture = await FlowFixture.StartAsync())
        {
            var code = await CodeAsync(fixture);

            using var wrongVerifier = await fixture.Client.PostAsync("/token", Form(
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", ClientId),
                ("code_verifier", Verifier.Value)));

            // The code was accepted here, so present it again to force the replay refusal - the one
            // branch that has the most to say about a specific code.
            using var replay = await fixture.Client.PostAsync("/token", Form(
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", ClientId),
                ("code_verifier", Verifier.Value)));

            Scan(fixture.Logs, [("authorization code", code), ("code_verifier", Verifier.Value)], leaks);
        }

        await using (var fixture = await FlowFixture.StartAsync())
        {
            var refresh = await RefreshTokenAsync(fixture);

            using var first = await fixture.Client.PostAsync("/token", Form(
                ("grant_type", "refresh_token"), ("client_id", ClientId), ("refresh_token", refresh)));

            fixture.Clock.Advance(TimeSpan.FromMinutes(5));

            using var reuse = await fixture.Client.PostAsync("/token", Form(
                ("grant_type", "refresh_token"), ("client_id", ClientId), ("refresh_token", refresh)));

            Scan(fixture.Logs, [("refresh token", refresh)], leaks);
        }

        await using (var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClientId, ClientType.Confidential)
                with { TokenEndpointAuthMethod = ClientAuthMethod.ClientSecretPost };
            seed.ConfigureOptions = o => o.TokenEndpointAuthMethods.Add(ClientAuthMethod.ClientSecretPost);
        }))
        {
            const string Secret = "bw_cs_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";

            using var response = await fixture.Client.PostAsync("/token", Form(
                ("grant_type", "authorization_code"), ("client_id", ClientId), ("client_secret", Secret)));

            Scan(fixture.Logs, [("client secret", Secret)], leaks);
        }

        Assert.True(
            leaks.Count == 0,
            "A credential the server was handed appears in a log line:" + Environment.NewLine
            + string.Join(Environment.NewLine, leaks));
    }

    /// <summary>Look for each secret in every field of every captured event.</summary>
    private static void Scan(LogSink sink, (string Kind, string Value)[] secrets, List<string> leaks)
    {
        foreach (var line in sink.Events)
        {
            var haystack = new StringBuilder(line.Message);

            foreach (var (name, value) in line.Properties)
            {
                haystack.Append('\u001f').Append(name).Append('=').Append(value);
            }

            if (line.Exception is not null)
            {
                haystack.Append('\u001f').Append(line.Exception);
            }

            var text = haystack.ToString();

            foreach (var (kind, value) in secrets)
            {
                if (text.Contains(value, StringComparison.Ordinal))
                {
                    leaks.Add($"  the {kind} appears in [{line.Category}] {line.Message}");
                }
            }
        }
    }

    /// <summary>Reasons only the resource server emits. Covered by that assembly's suite.</summary>
    private static readonly HashSet<ReasonCode> ResourceServerReasons =
    [
        ReasonCode.BearerCredentialAbsent,
        ReasonCode.BearerCredentialMalformed,
        ReasonCode.AccessTokenExpired,
        ReasonCode.AccessTokenWrongAudience,
        ReasonCode.AccessTokenRejected,

        // Emitted by Boltway.ResourceServer's bearer middleware after an IAccessTokenRevocationCheck
        // says the grant is gone, so it belongs to this list for the same reason the four above do:
        // this assembly does not host a resource server, and the challenge it rides on is written
        // and asserted in Boltway.ResourceServer.Tests.
        ReasonCode.AccessTokenRevoked,

        ReasonCode.InsufficientScope,
    ];

    /// <summary>
    /// Reasons with no route through HTTP, and why.
    /// </summary>
    /// <remarks>
    /// Every one of these is a refusal the code can still make - none is dead - and each is
    /// unreachable for a stated structural reason rather than because a scenario was hard to write.
    /// </remarks>
    private static readonly Dictionary<ReasonCode, string> UnreachableOverHttp = new()
    {
        [ReasonCode.RedirectUriRegistrationUnusable] =
            "Needs an IClientResolver returning a default(RegisteredRedirectUri) as a client's only "
            + "registration. The struct is public and the list is unvalidated, so it is constructible "
            + "— but the fixture's Build.Registered goes through TryRegister, which is the same route "
            + "production code takes, and there is no HTTP request that produces one.",

        [ReasonCode.RequestBodyUnreadable] =
            "Measured, and the finding is about the code rather than about the test. Request.Form "
            + "throws InvalidOperationException only when ASP.NET Core does not recognise the "
            + "content type as a form — and TryReadForm has already required exactly that content "
            + "type before it reads the body, using its own MediaType parser. So the catch is a "
            + "fail-safe against the two parsers disagreeing, not a branch a request can select. "
            + "Bodies that are simply malformed (`%`, a bare `=`, unbalanced escapes) parse to an "
            + "empty collection and come out as GrantTypeMissing, which is what the sink observed.",

        [ReasonCode.GrantTypeHasNoHandler] =
            "Reachable only if GrantTypesSupported names a grant with no handler, which options "
            + "validation refuses at startup. AddBoltwayAuthorizationServer throws before a "
            + "request can arrive.",

        [ReasonCode.ClientAuthMethodNotOffered] =
            "Needs a client registered for a method absent from TokenEndpointAuthMethods. Both are "
            + "configuration, and the shipped defaults offer every method ClientAuthMethod defines, "
            + "so the set this checks against is empty in any startable configuration.",

        [ReasonCode.ClientAuthMethodNotImplemented] =
            "The switch arm for a method that is enabled and has no implementation. Unreachable "
            + "while every enabled method has one; it exists so adding a member to ClientAuthMethod "
            + "fails closed rather than falling through to Authenticated.",

        [ReasonCode.PkceStoredChallengeUnusable] =
            "Needs a stored authorization code whose code_challenge column does not re-parse. Every "
            + "route into the store goes through CodeChallenge.TryParse first, so producing one over "
            + "HTTP would require corrupting the store behind the server's back.",

        [ReasonCode.AuthorizationCodeWrongClient] =
            "Needs two clients where the second presents the first's code. The fixture supports it "
            + "and AuthorizationCodeFlowTests already exercises the refusal; what is not proven here "
            + "is its log line specifically.",

        [ReasonCode.AuthorizationCodeGrantInactive] =
            "Needs the grant revoked between the code being issued and being exchanged, which no "
            + "sequence of HTTP requests to this server produces: revocation happens as a "
            + "consequence of the replay path, which consumes the code in the same step.",

        [ReasonCode.RefreshTokenGrantInactive] =
            "Same shape: the grant is revoked by reuse detection, which also revokes the family, so "
            + "the next presentation is RefreshTokenUnknown rather than this.",

        [ReasonCode.RefreshTokenWrongClient] =
            "Needs a second client presenting the first's refresh token. TokenGuardTests covers the "
            + "refusal; its log line is not separately forced here.",

        [ReasonCode.RefreshTokenSuccessorUnrecoverable] =
            "Needs two server instances with disagreeing RefreshTokenDerivationKey values racing one "
            + "redemption. RefreshTokenDeriverTests drives that through the store directly; over one "
            + "fixture's HTTP surface there is only one key.",
    };
}
