using System.Net;
using System.Text.Json;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.Storage.InMemory;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// A grant store that remembers which grants it was handed.
/// </summary>
/// <remarks>
/// Every <c>/authorize</c> mints a grant with a fresh <see cref="System.Guid"/>, so a test holding
/// an unexchanged authorization code has no way to name the grant behind it - and the two guards
/// below are both about what happens when that grant stops being active. This records the ids on
/// the way past and delegates everything else, which is the smallest seam that makes the question
/// askable. It adds nothing to the server.
/// </remarks>
internal sealed class RecordingGrantStore : IGrantStore
{
    private readonly InMemoryGrantStore _inner = new();
    private readonly List<string> _stored = [];
    private readonly Lock _gate = new();

    /// <summary>The grant ids in the order they were stored.</summary>
    public IReadOnlyList<string> Stored
    {
        get { lock (_gate) { return [.. _stored]; } }
    }

    public Task StoreAsync(GrantRecord grant, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _stored.Add(grant.GrantId);
        }

        return _inner.StoreAsync(grant, cancellationToken);
    }

    public Task<GrantRecord?> FindAsync(string grantId, CancellationToken cancellationToken) =>
        _inner.FindAsync(grantId, cancellationToken);

    public Task<bool> RevokeAsync(string grantId, DateTimeOffset now, CancellationToken cancellationToken) =>
        _inner.RevokeAsync(grantId, now, cancellationToken);

    public Task<int> RevokeAllForSubjectAsync(
        SubjectId subject, DateTimeOffset now, CancellationToken cancellationToken) =>
        _inner.RevokeAllForSubjectAsync(subject, now, cancellationToken);

    public Task<IReadOnlyList<GrantRecord>> ListForSubjectAsync(
        SubjectId subject, CancellationToken cancellationToken) =>
        _inner.ListForSubjectAsync(subject, cancellationToken);

    public Task<IReadOnlyList<string>> ListApprovedUserAgentsAsync(
        SubjectId subject, CancellationToken cancellationToken) =>
        _inner.ListApprovedUserAgentsAsync(subject, cancellationToken);

    public Task<bool> IsRevokedAsync(string grantId, CancellationToken cancellationToken) =>
        _inner.IsRevokedAsync(grantId, cancellationToken);
}

/// <summary>
/// What revocation actually revokes, observed in the store rather than inferred from a refusal.
/// </summary>
/// <remarks>
/// Both tests here exist because mutation testing found guards that no test could distinguish from
/// their absence. In each case the server behaves correctly; what was missing was any way to tell.
/// </remarks>
public sealed class GrantRevocationTests
{
    private const string ClientId = "https://claude.ai/.well-known/oauth-client";
    private const string RedirectUri = "https://claude.ai/api/mcp/auth_callback";

    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    private static Task<FlowFixture> StartAsync(RecordingGrantStore grants, SharedStores stores) =>
        FlowFixture.StartAsync(seed =>
        {
            seed.Stores = stores;

            // Applied after the fixture's own registrations, so this wins.
            seed.ConfigureServices = services => services.AddSingleton<IGrantStore>(grants);
        });

    private static async Task<string> GetCodeAsync(FlowFixture fixture)
    {
        var query = string.Join('&',
            "response_type=code",
            "client_id=" + Uri.EscapeDataString(ClientId),
            "redirect_uri=" + Uri.EscapeDataString(RedirectUri),
            "code_challenge=" + Verifier.ComputeS256Challenge(),
            "code_challenge_method=S256",
            "scope=" + Uri.EscapeDataString("mcp:tools offline_access"),
            "resource=" + Uri.EscapeDataString(Build.Resource),
            "state=opaque-state");

        var response = await fixture.Client.GetAsync("/authorize?" + query);

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var code = HttpUtility.ParseQueryString(new Uri(response.Headers.Location!.ToString()).Query)["code"];

        Assert.False(string.IsNullOrEmpty(code), "no code was issued");
        return code!;
    }

    private static FormUrlEncodedContent Exchange(string code) =>
        new(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["client_id"] = ClientId,
            ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = Verifier.Value,
        });

    private static FormUrlEncodedContent Refresh(string token) =>
        new(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = token,
            ["client_id"] = ClientId,
        });

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync()).RootElement.Clone();

    private static Sha256Hash HashOf(string refreshToken)
    {
        Assert.True(
            OpaqueSecret.TryParse(refreshToken, TokenPurpose.RefreshToken, out var secret),
            "the refresh token is not a well-formed refresh token");

        return Sha256Hash.Of(secret);
    }

    /// <summary>
    /// A code whose grant was revoked between issue and exchange is refused.
    /// </summary>
    /// <remarks>
    /// <c>if (grant is null || !grant.IsActive)</c> in <c>GrantHandlers</c>, mutated to
    /// <c>&amp;&amp;</c>, survived the suite. Under the mutant a grant that <i>exists but is
    /// revoked</i> evaluates <c>false &amp;&amp; true</c> and the guard does not fire, so the code
    /// redeems against a dead grant and the server issues tokens for an authorization the user or an
    /// administrator has already withdrawn.
    /// </remarks>
    [Fact]
    public async Task A_code_whose_grant_was_revoked_cannot_be_exchanged()
    {
        var grants = new RecordingGrantStore();
        await using var fixture = await StartAsync(grants, new SharedStores());

        var code = await GetCodeAsync(fixture);

        // The grant exists from the moment the code is issued, which is what makes this reachable:
        // the window between issue and exchange is exactly where a withdrawal lands.
        var grantId = Assert.Single(grants.Stored);
        Assert.True(await grants.RevokeAsync(grantId, DateTimeOffset.UtcNow, CancellationToken.None));

        var response = await fixture.Client.PostAsync("/token", Exchange(code));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_grant", (await ReadJsonAsync(response)).GetProperty("error").GetString());
    }

    /// <summary>
    /// Reuse detection revokes the family <b>and</b> the grant, checked separately.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 9700 §2.2.2. The handler does two things on a detected replay:
    /// </para>
    /// <code>
    /// await _refreshTokens.RevokeFamilyAsync(reuse.FamilyId, now, cancellationToken);
    /// await _grants.RevokeAsync(reuse.GrantId, now, cancellationToken);
    /// </code>
    /// <para>
    /// Mutation testing deleted each line on its own and the suite stayed green both times - not
    /// because the behaviour is unchecked, but because the existing test checks it through a
    /// <i>consequence the two calls share</i>. <c>A_replay_outside_the_grace_window_revokes_the_family</c>
    /// asserts that the successor refresh token stops working, and it stops working under either
    /// revocation alone. Each line is masked by the other, so neither is independently proven and
    /// removing one as redundant would leave a real hole with nothing to catch it.
    /// </para>
    /// <para>
    /// This test looks in the two stores separately, so each assertion depends on exactly one of the
    /// two calls.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_detected_replay_revokes_the_family_and_the_grant_independently()
    {
        var grants = new RecordingGrantStore();
        var stores = new SharedStores();

        await using var fixture = await StartAsync(grants, stores);

        var first = await ReadJsonAsync(await fixture.Client.PostAsync("/token", Exchange(await GetCodeAsync(fixture))));
        var original = first.GetProperty("refresh_token").GetString()!;

        var rotated = await ReadJsonAsync(await fixture.Client.PostAsync("/token", Refresh(original)));
        var successor = rotated.GetProperty("refresh_token").GetString()!;

        // Past the grace window, so the replay is a reuse rather than a retried delivery.
        fixture.Clock.Advance(TimeSpan.FromMinutes(5));

        var replay = await fixture.Client.PostAsync("/token", Refresh(original));

        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Equal("invalid_grant", (await ReadJsonAsync(replay)).GetProperty("error").GetString());

        var record = await stores.RefreshTokens.FindAsync(HashOf(successor), CancellationToken.None);

        Assert.NotNull(record);

        // (2) the grant: asked of the grant store, which the family revocation never touches. The
        // grant id comes from the token record rather than from Stored[0], so this still names the
        // right grant if the flow ever mints more than one.
        Assert.True(
            await grants.IsRevokedAsync(record!.GrantId, CancellationToken.None),
            "the grant was not revoked");

        // (1) the family: asked of the refresh token store, which the grant revocation never
        // touches. There is no IsFamilyRevoked query, so this uses the one the store documents -
        // "a second revoke returns 0 and a caller can log honestly". Revoking an already-revoked
        // family transitions no rows; revoking a live one transitions at least the successor. Last
        // assertion in the test because it does write to the store.
        Assert.NotNull(record);
        Assert.Equal(
            0,
            await stores.RefreshTokens.RevokeFamilyAsync(
                record!.FamilyId, DateTimeOffset.UtcNow, CancellationToken.None));
    }
}
