using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Configuration;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// "Ask once": a consent stands while it covers the request, and not a scope or a resource further.
/// </summary>
/// <remarks>
/// The comparison <c>AlwaysAskConsentPolicy</c>'s remarks say a deployment owes, made by the policy
/// itself rather than left for the guard to correct. Each refusal here has the covering case as its
/// control, so a policy that always answered <c>Required</c> fails the first test and one that
/// answered <c>AlreadyGranted</c> whenever a record existed fails the next two.
/// </remarks>
public sealed class RememberedConsentPolicyTests
{
    private static readonly SubjectId Subject = SubjectId.FromStorage("user-1");

    private static async Task<ConsentDecision> DecideAsync(
        string? granted,
        string requested,
        IReadOnlyList<string>? grantedResources = null,
        IReadOnlyList<string>? requestedResources = null,
        ClientRecord? client = null)
    {
        Assert.True(ScopeSet.TryParse(requested, out var requestedScope, out _));

        client ??= Build.Client(type: ClientType.Confidential);

        ConsentRecord? record = null;

        if (granted is not null)
        {
            Assert.True(ScopeSet.TryParse(granted, out var grantedScope, out _));
            record = new ConsentRecord(
                Subject, client.ClientId, grantedScope, grantedResources ?? [Build.Resource], DateTimeOffset.UnixEpoch);
        }

        return await new PublicClientReconsentGuard(new RememberedConsentPolicy()).DecideAsync(
            new ConsentContext(client, Subject, requestedScope, requestedResources ?? [Build.Resource], record),
            CancellationToken.None);
    }

    [Fact]
    public async Task A_consent_covering_the_request_stands()
    {
        Assert.Equal(ConsentDecision.AlreadyGranted, await DecideAsync(granted: "mcp:tools offline_access", requested: "mcp:tools"));
    }

    [Fact]
    public async Task No_record_is_asked()
    {
        Assert.Equal(ConsentDecision.Required, await DecideAsync(granted: null, requested: "mcp:tools"));
    }

    [Fact]
    public async Task One_more_scope_is_asked()
    {
        Assert.Equal(ConsentDecision.Required, await DecideAsync(granted: "mcp:tools", requested: "mcp:tools offline_access"));
    }

    [Fact]
    public async Task A_resource_the_user_never_saw_is_asked()
    {
        Assert.Equal(
            ConsentDecision.Required,
            await DecideAsync(granted: "mcp:tools", requested: "mcp:tools", requestedResources: [Build.OtherResource]));
    }

    /// <summary>
    /// Not a way round the public-client rule: a client that describes itself is asked however
    /// complete its record is.
    /// </summary>
    [Fact]
    public async Task A_public_client_whose_redirect_proves_nothing_is_still_asked()
    {
        Assert.Equal(
            ConsentDecision.Required,
            await DecideAsync(granted: "mcp:tools", requested: "mcp:tools", client: Build.Client(type: ClientType.Public)));
    }

    /// <summary>The control for the test above: the same record, the redirect vouched for.</summary>
    [Fact]
    public async Task A_public_client_whose_https_redirect_proves_identity_is_remembered()
    {
        var client = Build.Client(type: ClientType.Public) with { RedirectProvesIdentity = true };

        Assert.Equal(
            ConsentDecision.AlreadyGranted,
            await DecideAsync(granted: "mcp:tools", requested: "mcp:tools", client: client));
    }
}
