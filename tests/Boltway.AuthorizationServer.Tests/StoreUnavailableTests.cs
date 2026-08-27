using System.Data.Common;
using System.Net;
using System.Net.Sockets;
using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.OAuth.Primitives.Secrets;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// X-43: a store that cannot be reached load-sheds rather than crashing.
/// </summary>
/// <remarks>
/// <para>
/// Written from a production failure rather than from imagination. 2026-08-22 03:43:16 UTC, DNS for
/// the database host failed with <c>EAI_AGAIN</c>; the driver exception reached <c>/token</c>
/// unhandled and became a bare <c>500</c> after five seconds. The client stopped refreshing,
/// replayed its expired access token, then sent none at all, and the person holding it was told to
/// check their credentials and permissions. Both were fine. The store answered normally seventy
/// seconds later.
/// </para>
/// <para>
/// Two directions are asserted and the second is the one that keeps this honest. A transient
/// failure must become <c>503</c> with a <c>Retry-After</c> - and an ordinary defect must not,
/// because a bug dressed as "come back shortly" is a bug every client retries forever and nobody
/// sees.
/// </para>
/// </remarks>
public sealed partial class StoreUnavailableTests
{
    private const string ClientId = "https://claude.ai/.well-known/oauth-client";

    /// <summary>What a provider raises when it cannot reach the server.</summary>
    /// <remarks>
    /// <see cref="DbException.IsTransient"/> is the framework's own contract for "this may be
    /// retried", which is what <see cref="TransientStoreFailure"/> reads instead of matching on
    /// message text. Npgsql sets it for exactly this class of failure.
    /// </remarks>
    private sealed class UnreachableException(string message) : DbException(message)
    {
        public override bool IsTransient => true;
    }

    /// <summary>
    /// The shape production raised, for every store double in this file and its partial.
    /// </summary>
    /// <remarks>
    /// EF Core recognises a transient provider error and, with <c>EnableRetryOnFailure</c> off -
    /// which DESIGN §1.2 requires on <c>/token</c> - rethrows it wrapped. Testing the bare driver
    /// exception would pass while the wrapped one, which is the only one an endpoint ever sees,
    /// still became a 500.
    /// </remarks>
    private static InvalidOperationException Unreachable() => new(
        "An exception has been raised that is likely due to a transient failure.",
        new UnreachableException("Resource temporarily unavailable"));

    /// <summary>A refresh token store with nothing behind it.</summary>
    /// <remarks>
    /// Every method throws, because the point is the connection rather than the query: a store that
    /// cannot be reached fails whichever method the grant happens to call first, and pinning the
    /// test to one of them would pin it to an implementation detail of the grant handler.
    /// </remarks>
    private sealed class UnreachableRefreshTokenStore : IRefreshTokenStore
    {
        public Task<RefreshTokenRecord?> FindAsync(Sha256Hash tokenHash, CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task StoreAsync(RefreshTokenRecord record, CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task<RefreshRedemption> RedeemAsync(
            Sha256Hash presented,
            RefreshTokenSeed successor,
            DateTimeOffset now,
            TimeSpan graceWindow,
            CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task<int> RevokeFamilyAsync(string familyId, DateTimeOffset now, CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task<IReadOnlyDictionary<string, DateTimeOffset>> LastIssuedForGrantsAsync(
            IReadOnlyCollection<string> grantIds, CancellationToken cancellationToken) =>
            throw Unreachable();

    }

    private static async Task<FlowFixture> UnreachableStoreAsync() =>
        await FlowFixture.StartAsync(seed => seed.ConfigureServices = services =>
            services.AddSingleton<IRefreshTokenStore>(new UnreachableRefreshTokenStore()));

    /// <summary>
    /// A refresh token that is well-formed and unknown.
    /// </summary>
    /// <remarks>
    /// Minted rather than invented, because the grant parses before it queries: an arbitrary string
    /// is refused as malformed and never reaches the store, which made a first draft of these tests
    /// pass on a 400 while asserting nothing about the failure they exist for. Whether the store
    /// would have recognised it does not matter here - it never answers.
    /// </remarks>
    private static FormUrlEncodedContent Refresh() =>
        new(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = OpaqueSecret.Generate(TokenPurpose.RefreshToken).Wire,
            ["client_id"] = ClientId,
        });

    // ── the endpoint ─────────────────────────────────────────────────────────

    /// <summary>503, not 500, and with the header that makes it actionable.</summary>
    /// <remarks>
    /// The status and <c>Retry-After</c> together are the entire signal: a client reading them backs
    /// off and keeps its grant, where a 500 tells it the request cannot succeed and says nothing
    /// about when it might.
    /// </remarks>
    [Fact]
    public async Task A_store_that_cannot_be_reached_answers_503_with_a_retry_after()
    {
        await using var fixture = await UnreachableStoreAsync();

        var response = await fixture.Client.PostAsync("/token", Refresh());

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);

        var retryAfter = response.Headers.RetryAfter;
        Assert.NotNull(retryAfter);
        Assert.NotNull(retryAfter!.Delta);

        // Never zero: "retry immediately" is what the caller was just told not to do.
        Assert.True(
            retryAfter.Delta!.Value > TimeSpan.Zero,
            $"Retry-After was {retryAfter.Delta}, which tells the client to hammer a dependency that is down.");
    }

    /// <summary>No <c>error</c> member, because RFC 6749 §5.2 registers none that means this.</summary>
    /// <remarks>
    /// <c>temporarily_unavailable</c> is the code that means exactly this and it belongs to
    /// §4.1.2.1, the authorization endpoint. Emitting it here would be an invention on the one
    /// endpoint whose error strings clients branch on hardest, and <c>{"error":""}</c> is worse
    /// still - a member the RFC says must be one of a closed set, holding a value in no set at all.
    /// </remarks>
    [Fact]
    public async Task The_load_shed_invents_no_error_code()
    {
        await using var fixture = await UnreachableStoreAsync();

        var response = await fixture.Client.PostAsync("/token", Refresh());
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(string.Empty, body);

        // The one header this response does carry a body-shaped obligation about: never reused.
        Assert.Contains("no-store", response.Headers.CacheControl?.ToString() ?? string.Empty, StringComparison.Ordinal);
    }

    /// <summary>A-09 holds here too: the refusal is one structured line naming X-43.</summary>
    /// <remarks>
    /// The 503 is built inside the endpoint rather than by middleware precisely so it travels the
    /// rejection writer. If it stopped doing so, the response would still look right and the outage
    /// would become invisible - which is the failure mode A-09 exists to remove, arriving on the one
    /// refusal that means the database is gone.
    /// </remarks>
    [Fact]
    public async Task The_load_shed_is_logged_once_like_every_other_refusal()
    {
        await using var fixture = await UnreachableStoreAsync();

        var response = await fixture.Client.PostAsync("/token", Refresh());

        var line = Assert.Single(fixture.Logs.Rejections);

        Assert.Equal("Token", line.Property("Surface"));
        Assert.Equal("StoreUnavailable", line.Property("Reason"));
        Assert.Equal("X-43", line.Property("RequirementId"));

        // The id in the log is the id the caller holds, which is what makes a user's report
        // resolvable to this line.
        Assert.Equal(
            response.Headers.GetValues("X-Request-Id").Single(),
            line.Property("CorrelationId"));
    }

    /// <summary>The driver's message never reaches the wire.</summary>
    /// <remarks>
    /// A connection failure names the host, the database, the role and often the driver version.
    /// This response is readable by anyone who can reach the endpoint, so the detail goes to the log
    /// and the wire gets the exception's type name at most.
    /// </remarks>
    [Fact]
    public async Task Nothing_about_the_database_reaches_the_caller()
    {
        await using var fixture = await UnreachableStoreAsync();

        var response = await fixture.Client.PostAsync("/token", Refresh());
        var wire = await response.Content.ReadAsStringAsync() + response.Headers;

        Assert.DoesNotContain("Resource temporarily unavailable", wire, StringComparison.Ordinal);
        Assert.DoesNotContain("transient failure", wire, StringComparison.OrdinalIgnoreCase);
    }

    // ── the classifier, both directions ──────────────────────────────────────

    /// <summary>The shape production actually raised.</summary>
    [Fact]
    public void A_transient_driver_failure_wrapped_by_ef_core_is_recognised() =>
        Assert.True(TransientStoreFailure.Describes(new InvalidOperationException(
            "An exception has been raised that is likely due to a transient failure.",
            new UnreachableException("Resource temporarily unavailable"))));

    /// <summary>A name-resolution failure, which is what EAI_AGAIN surfaces as.</summary>
    [Fact]
    public void A_socket_failure_is_recognised_however_deeply_it_is_wrapped() =>
        Assert.True(TransientStoreFailure.Describes(
            new InvalidOperationException("outer", new AggregateException(
                new InvalidCastException("unrelated"),
                new SocketException((int)SocketError.TryAgain)))));

    /// <summary>
    /// An ordinary defect is not a load-shed, and this is the assertion that keeps the fix from
    /// becoming a bug-hider.
    /// </summary>
    /// <remarks>
    /// <c>NullReferenceException</c> and a non-transient <see cref="DbException"/> both mean the
    /// request cannot succeed by retrying. Classifying either as transient would answer 503, and a
    /// client honouring <c>Retry-After</c> would then retry a defect until someone noticed by other
    /// means.
    /// </remarks>
    [Theory]
    [MemberData(nameof(NotTransient))]
    public void A_defect_is_not_dressed_up_as_come_back_later(Exception defect) =>
        Assert.False(TransientStoreFailure.Describes(defect));

    public static TheoryData<Exception> NotTransient() =>
    [
        new InvalidCastException("a real bug"),
        new InvalidOperationException("a real bug"),
        new NotTransientException("constraint violated"),
        new InvalidOperationException("wrapped", new NotTransientException("constraint violated")),

        // A client that disconnects mid-request. The store was never the problem, and answering
        // 503 would count a cancelled request as an outage in whatever watches for them.
        new OperationCanceledException("the caller went away"),
    ];

    /// <summary>A database error that retrying cannot fix.</summary>
    private sealed class NotTransientException(string message) : DbException(message)
    {
        public override bool IsTransient => false;
    }

    /// <summary>Null is not a failure of any kind.</summary>
    [Fact]
    public void Nothing_is_not_a_store_failure() => Assert.False(TransientStoreFailure.Describes(null));
}
