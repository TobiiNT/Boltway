using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Standing consent covers what it covers, and no more.
/// </summary>
/// <remarks>
/// <para>
/// <c>ConsentDecision.AlreadyGranted</c> is documented as "they already agreed to <b>at least this
/// much</b>", so the comparison belongs to whoever answers. The natural first draft -
/// <c>context.Existing is not null ? AlreadyGranted : Required</c> - does not make it, and a review
/// executed that draft: with a record covering <c>mcp:tools</c> on one resource and a request for
/// <c>mcp:tools offline_access openid</c> on a <i>different</i> resource, the flow returned a code
/// with no consent page, then an access token whose <c>aud</c> was a resource the user had never
/// seen. Under <c>prompt=none</c> it returned a code where X-13 requires <c>consent_required</c>.
/// </para>
/// <para>
/// The check lives in <see cref="PublicClientReconsentGuard"/>, which the server composes at the one
/// call site, so a customer's policy cannot skip it. These tests drive the guard directly because
/// the escalation is a property of the decision, not of the transport - and because the shipped
/// default policy always answers <c>Required</c>, so no HTTP-level test can reach it without
/// substituting the very draft being guarded against.
/// </para>
/// </remarks>
public sealed class ConsentSubsetTests
{
    /// <summary>The policy a customer writes first, and the one this guard exists to correct.</summary>
    private sealed class RecordExistsMeansGranted : IConsentPolicy
    {
        public ValueTask<ConsentDecision> DecideAsync(ConsentContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(
                context.Existing is null ? ConsentDecision.Required : ConsentDecision.AlreadyGranted);
    }

    [Fact]
    public async Task A_wider_scope_than_the_record_is_asked_again()
    {
        var decision = await DecideAsync(
            granted: "mcp:tools",
            requested: "mcp:tools offline_access openid",
            grantedResources: [Build.Resource],
            requestedResources: [Build.Resource]);

        Assert.Equal(ConsentDecision.Required, decision);
    }

    [Fact]
    public async Task A_resource_the_record_does_not_cover_is_asked_again()
    {
        var decision = await DecideAsync(
            granted: "mcp:tools",
            requested: "mcp:tools",
            grantedResources: [Build.Resource],
            requestedResources: [Build.OtherResource]);

        Assert.Equal(ConsentDecision.Required, decision);
    }

    /// <summary>
    /// The control: a request inside the record still proceeds without asking.
    /// </summary>
    /// <remarks>
    /// Without this, both tests above are satisfied by a guard that returns <c>Required</c>
    /// unconditionally - which is safe, useless, and would mean standing consent never worked at
    /// all.
    /// </remarks>
    [Fact]
    public async Task A_request_inside_the_record_is_not_asked_again()
    {
        var decision = await DecideAsync(
            granted: "mcp:tools offline_access",
            requested: "mcp:tools",
            grantedResources: [Build.Resource, Build.OtherResource],
            requestedResources: [Build.Resource]);

        Assert.Equal(ConsentDecision.AlreadyGranted, decision);
    }

    /// <summary>
    /// Scope names are compared ordinally, so a differently-cased scope is a different scope.
    /// </summary>
    /// <remarks>
    /// OAuth 2.1 §1.4.1 makes scope values case-sensitive. A case-insensitive comparison here would
    /// treat a record for <c>mcp:tools</c> as covering a request for <c>MCP:TOOLS</c> - which, if
    /// the server also registered both, would grant one the user never approved.
    /// </remarks>
    [Fact]
    public async Task A_differently_cased_scope_is_not_covered_by_the_record()
    {
        var decision = await DecideAsync(
            granted: "mcp:tools",
            requested: "MCP:TOOLS",
            grantedResources: [Build.Resource],
            requestedResources: [Build.Resource]);

        Assert.Equal(ConsentDecision.Required, decision);
    }

    /// <summary>
    /// A policy asserting consent this server never recorded is still trusted.
    /// </summary>
    /// <remarks>
    /// An organisation that pre-approves its own first-party clients, or one whose consent lives in
    /// another system, legitimately answers <c>AlreadyGranted</c> with no local record. Refusing
    /// that would break a real design and catch nothing - the draft this guard corrects returns
    /// <c>Required</c> in exactly that case. The escalation needs a record covering <i>less</i> than
    /// the request, which is the condition the guard checks.
    /// </remarks>
    [Fact]
    public async Task A_policy_with_no_record_at_all_is_left_alone()
    {
        var guard = new PublicClientReconsentGuard(new AlwaysGranted());

        Assert.True(ScopeSet.TryParse("mcp:tools", out var requested, out _));

        var decision = await guard.DecideAsync(
            new ConsentContext(
                Build.Client(type: ClientType.Confidential),
                SubjectId.FromStorage("user-1"),
                requested,
                [Build.Resource],
                Existing: null),
            CancellationToken.None);

        Assert.Equal(ConsentDecision.AlreadyGranted, decision);
    }

    /// <summary>A public client is asked again regardless - RFC 8252 §8.6, the guard's first rule.</summary>
    [Fact]
    public async Task A_public_client_is_asked_again_even_inside_the_record()
    {
        var decision = await DecideAsync(
            granted: "mcp:tools",
            requested: "mcp:tools",
            grantedResources: [Build.Resource],
            requestedResources: [Build.Resource],
            clientType: ClientType.Public);

        Assert.Equal(ConsentDecision.Required, decision);
    }

    private sealed class AlwaysGranted : IConsentPolicy
    {
        public ValueTask<ConsentDecision> DecideAsync(ConsentContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(ConsentDecision.AlreadyGranted);
    }

    private static async Task<ConsentDecision> DecideAsync(
        string granted,
        string requested,
        IReadOnlyList<string> grantedResources,
        IReadOnlyList<string> requestedResources,
        ClientType clientType = ClientType.Confidential)
    {
        Assert.True(ScopeSet.TryParse(granted, out var grantedScope, out _));
        Assert.True(ScopeSet.TryParse(requested, out var requestedScope, out _));

        var client = Build.Client(type: clientType);
        var subject = SubjectId.FromStorage("user-1");

        var record = new ConsentRecord(
            subject, client.ClientId, grantedScope, grantedResources, DateTimeOffset.UnixEpoch);

        var guard = new PublicClientReconsentGuard(new RecordExistsMeansGranted());

        return await guard.DecideAsync(
            new ConsentContext(client, subject, requestedScope, requestedResources, record),
            CancellationToken.None);
    }
}
