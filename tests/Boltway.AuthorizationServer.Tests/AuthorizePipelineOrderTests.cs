using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Authorize;
using Boltway.OAuth.Primitives.Diagnostics;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The order of the post-redirect validation chain, and four limits nothing had exercised.
/// </summary>
/// <remarks>
/// From the mutation run on <c>AuthorizePipeline.cs</c>: 76 survivors, of which 61 were string
/// mutations in diagnostic text and 15 were behavioural. These cover the five that change what a
/// client receives. The rest are named at the bottom of this file with the reason they are not
/// worth a test, rather than left as unexplained survivors.
/// </remarks>
public sealed class AuthorizePipelineOrderTests
{
    private static async Task<AuthorizeOutcome> RunAsync(
        Dictionary<string, string[]> parameters, AuthorizePipeline? pipeline = null) =>
        await (pipeline ?? Build.Pipeline()).ValidateAsync(Build.Context(parameters), CancellationToken.None);

    private static Dictionary<string, string[]> Request(params (string Key, string[] Values)[] overrides)
    {
        var request = Build.ValidRequest();

        foreach (var (key, values) in overrides)
        {
            if (values.Length == 0)
            {
                request.Remove(key);
            }
            else
            {
                request[key] = values;
            }
        }

        return request;
    }

    private static ReasonCode ReasonOf(AuthorizeOutcome outcome) =>
        Assert.IsType<AuthorizeOutcome.Redirect>(outcome).Error.Rejection.Reason;

    // ─────────────────────────────────────────────────────────────────────────
    // the chain order
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A request that fails two stages reports the earlier one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The chain is five <c>??</c> links:
    /// </para>
    /// <code>
    /// ValidateResponseType(...) ?? ValidatePkce(...) ?? ValidateScope(...)
    ///     ?? await ValidateResourcesAsync(...) ?? ValidateOidcParameters(...)
    /// </code>
    /// <para>
    /// Mutation testing reordered it four different ways and every one survived. Nothing in the
    /// suite had ever sent a request that fails <b>two</b> stages at once, so no test could tell
    /// this order from any other. Each row below breaks one link: it violates two adjacent stages
    /// and names the earlier stage's reason.
    /// </para>
    /// <para>
    /// Every row must violate <b>both</b> stages, and that is not a stylistic point. Stryker emits
    /// three mutators per <c>??</c>: remove-left, remove-right, and <i>left-to-right</i>, which
    /// <b>swaps</b> the operands rather than deleting one. A row with a single violation kills the
    /// two removals and leaves the swap alive, because the swapped chain finds nothing in the later
    /// stages and falls back to the operand it was supposed to have run first - the same answer, by
    /// a different route. The first version of the first row did exactly that, and the re-measured
    /// run is what found it.
    /// </para>
    /// <para>
    /// This is not cosmetic. OAuth clients branch on the error code, and a client told
    /// <c>invalid_scope</c> when its real problem is a missing <c>code_challenge</c> will go and
    /// edit the wrong thing. It is also the property the file's own header claims - "the ordering
    /// property first" - and the ordering above the redirect gate is enforced structurally by
    /// passing <c>redirect</c> as an argument, while the ordering <i>below</i> it was enforced by
    /// nothing at all.
    /// </para>
    /// </remarks>
    [Theory]
    // response_type before pkce. The challenge is removed as well as the response type broken -
    // passing null here would leave a VALID challenge, so only one stage would fail and the row
    // would prove nothing about order. That was the first version, and the re-run caught it: with
    // one violation the swapped chain finds nothing in the later stages and falls back to
    // ValidateResponseType, producing the same answer.
    [InlineData("token", "", null, null, null, ReasonCode.ResponseTypeUnsupported)]
    // pkce before scope
    [InlineData(null, "", "not-a-real-scope", null, null, ReasonCode.PkceChallengeMissing)]
    // scope before resource
    [InlineData(null, null, "not-a-real-scope", "not-a-uri", null, ReasonCode.ScopeUnsupported)]
    // resource before the oidc parameters
    [InlineData(null, null, null, "not-a-uri", "none login", ReasonCode.ResourceMalformed)]
    public async Task The_chain_reports_the_earlier_of_two_failures(
        string? responseType,
        string? codeChallenge,
        string? scope,
        string? resource,
        string? prompt,
        ReasonCode expected)
    {
        var overrides = new List<(string, string[])>();

        if (responseType is not null) { overrides.Add(("response_type", [responseType])); }
        if (codeChallenge is not null) { overrides.Add(("code_challenge", codeChallenge.Length == 0 ? [] : [codeChallenge])); }
        if (scope is not null) { overrides.Add(("scope", [scope])); }
        if (resource is not null) { overrides.Add(("resource", [resource])); }
        if (prompt is not null) { overrides.Add(("prompt", [prompt])); }

        Assert.Equal(expected, ReasonOf(await RunAsync(Request([.. overrides]))));
    }

    /// <summary>
    /// The control: each violation on its own really does produce the reason the rows above expect.
    /// </summary>
    /// <remarks>
    /// Without this, a row could pass because the <i>later</i> violation was not a violation at all
    /// - the request would fail one stage, the assertion would hold, and the ordering would be
    /// untested while looking tested.
    /// </remarks>
    [Theory]
    [InlineData("response_type", "token", ReasonCode.ResponseTypeUnsupported)]
    [InlineData("scope", "not-a-real-scope", ReasonCode.ScopeUnsupported)]
    [InlineData("resource", "not-a-uri", ReasonCode.ResourceMalformed)]
    [InlineData("prompt", "none login", ReasonCode.PromptCombinationInvalid)]
    public async Task Each_violation_alone_produces_its_own_reason(string key, string value, ReasonCode expected)
    {
        Assert.Equal(expected, ReasonOf(await RunAsync(Request((key, [value])))));
    }

    [Fact]
    public async Task A_missing_challenge_alone_produces_the_pkce_reason()
    {
        Assert.Equal(
            ReasonCode.PkceChallengeMissing,
            ReasonOf(await RunAsync(Request(("code_challenge", [])))));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // limits that had never been exercised
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A throttled resolver's own <c>Retry-After</c> reaches the client.
    /// </summary>
    /// <remarks>
    /// <c>resolution.RetryAfter ?? TimeSpan.FromSeconds(60)</c>, mutated to drop the left operand,
    /// survived: nothing asserted the value, only that a rate-limited resolver produced the
    /// throttled outcome. A resolver that knows its budget resets in ten minutes would have been
    /// telling every client to come back in sixty seconds, and X-31 exists precisely because
    /// "when to try again" is the fact that makes the response actionable.
    /// </remarks>
    [Fact]
    public async Task A_throttled_resolvers_own_retry_after_is_carried_not_replaced()
    {
        var resolver = new TestClientResolver(Build.Client())
        {
            ForcedFailure = ClientResolution.RateLimited("spent", TimeSpan.FromMinutes(10)),
        };

        var outcome = await RunAsync(Build.ValidRequest(), Build.Pipeline(resolver));

        var html = Assert.IsType<AuthorizeOutcome.Html>(outcome);

        Assert.Equal(ReasonCode.RateLimited, html.Error.Rejection.Reason);
        Assert.Equal(TimeSpan.FromMinutes(10), html.Error.RetryAfter);
    }

    /// <summary>
    /// A client that declared no grant types is not thereby refused.
    /// </summary>
    /// <remarks>
    /// <c>client.GrantTypes.Count &gt; 0 &amp;&amp; !Contains("authorization_code")</c> mutated to
    /// <c>&gt;= 0</c> survived, because every client in the suite declares its grants. Under the
    /// mutant an empty list means "refuse everything" rather than "declared no restriction", and
    /// the <c>Count &gt; 0</c> guard is the whole statement that the check is opt-in.
    /// </remarks>
    [Fact]
    public async Task A_client_that_declared_no_grant_types_is_not_refused()
    {
        var client = Build.Client() with { GrantTypes = [] };

        var outcome = await RunAsync(Build.ValidRequest(), Build.Pipeline(new TestClientResolver(client)));

        Assert.IsType<AuthorizeOutcome.Validated>(outcome);
    }

    [Fact]
    public async Task A_client_that_declared_other_grant_types_is_refused()
    {
        // The control for the test above: the check still bites when the list is non-empty.
        var client = Build.Client() with { GrantTypes = ["refresh_token"] };

        var outcome = await RunAsync(Build.ValidRequest(), Build.Pipeline(new TestClientResolver(client)));

        Assert.Equal(ReasonCode.ClientNotRegisteredForGrantType, ReasonOf(outcome));
    }

    /// <summary>
    /// A client with an allowed-scope list may request scopes that are on it.
    /// </summary>
    /// <remarks>
    /// <c>!AllowedScopes.IsEmpty &amp;&amp; requested.Except(AllowedScopes).Count &gt; 0</c> mutated
    /// to <c>&gt;= 0</c> survived. Under the mutant <b>every</b> client with a non-empty allow-list
    /// is refused every request, because the count is always at least zero - so the survival says
    /// no test had ever given a client an allow-list and then asked for something on it. The
    /// narrowing had only ever been proven to refuse, never to permit.
    /// </remarks>
    [Fact]
    public async Task A_scope_on_the_clients_allow_list_is_permitted()
    {
        var client = Build.Client() with { AllowedScopes = Build.Scopes("mcp:tools offline_access") };

        var outcome = await RunAsync(Build.ValidRequest(), Build.Pipeline(new TestClientResolver(client)));

        Assert.IsType<AuthorizeOutcome.Validated>(outcome);
    }

    [Fact]
    public async Task A_scope_off_the_clients_allow_list_is_refused()
    {
        // The control. Without it, the test above passes against a server that ignores the list.
        var client = Build.Client() with { AllowedScopes = Build.Scopes("story:read") };

        var outcome = await RunAsync(Build.ValidRequest(), Build.Pipeline(new TestClientResolver(client)));

        Assert.Equal(ReasonCode.ScopeNotAllowedForClient, ReasonOf(outcome));
    }

    /// <summary>
    /// The resource-count limit is inclusive: exactly the maximum is allowed.
    /// </summary>
    /// <remarks>
    /// <c>raw.Count &gt; MaxResourceValues</c> mutated to <c>&gt;=</c> survived - the classic
    /// off-by-one, and the classic reason: no test had ever sent exactly the boundary. A limit
    /// documented as "at most 16" that refuses the sixteenth is a different limit.
    /// </remarks>
    [Theory]
    [InlineData(AuthorizePipeline.MaxResourceValues, false)]
    [InlineData(AuthorizePipeline.MaxResourceValues + 1, true)]
    public async Task The_resource_count_limit_is_inclusive(int count, bool refused)
    {
        var values = Enumerable.Repeat(Build.Resource, count).ToArray();

        var outcome = await RunAsync(Request(("resource", values)));

        if (refused)
        {
            Assert.Equal(ReasonCode.ResourceTooMany, ReasonOf(outcome));
        }
        else
        {
            Assert.IsType<AuthorizeOutcome.Validated>(outcome);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The behavioural survivors left alive on purpose, and why
    // ─────────────────────────────────────────────────────────────────────────
    //
    // line  87  ArgumentNullException.ThrowIfNull(context) removed. The guard turns a
    //           NullReferenceException into an ArgumentNullException on an internal call path that
    //           no request can reach with a null context. Testing it would pin the exception type
    //           of a programming error, not a behaviour any client observes.
    //
    // lines 153, 451  Ternaries choosing between two private log detail strings -
    //           "client_id absent" versus "client_id={raw}". A-09's contract is the ReasonCode and
    //           the correlation id, both already asserted in RejectionLoggingTests; the detail text
    //           is not a contract with anybody. Six survivors, all diagnostic.
    //
    // Plus 61 string mutations, all in descriptions and detail strings. Measured across the whole
    // assembly: exactly one string survivor anywhere touched a protocol-visible literal.
}
