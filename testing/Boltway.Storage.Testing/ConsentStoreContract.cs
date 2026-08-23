using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.Storage.Testing;

/// <summary>
/// The <see cref="IConsentStore"/> contract, run against every implementation.
/// </summary>
/// <remarks>
/// <para>
/// The third suite, and the one with the shortest rule: <b>consent widens, it never replaces</b>.
/// C-24. A client that comes back asking for one more scope must end up with the union, because
/// replacing silently revokes authority the user granted earlier and never withdrew — and the
/// symptom is a tool that worked yesterday returning 403 today, with a consent record that looks
/// perfectly reasonable.
/// </para>
/// <para>
/// It is written down here because the obvious first draft gets it wrong and this repository has the
/// receipts: the only <see cref="IConsentStore"/> implementation that existed before
/// <c>InMemoryConsentStore</c> was a test double doing <c>_records[key] = record</c>. So the most
/// likely shape of a customer's first attempt is the one the repository itself had written.
/// </para>
/// </remarks>
public abstract class ConsentStoreContract
{
    /// <summary>A fresh, empty consent store.</summary>
    protected abstract IConsentStore NewConsentStore();

    private static readonly ClientIdentifier Claude =
        ClientIdentifier.ForCimd("https://claude.ai/oauth/mcp-oauth-client-metadata");

    private static readonly ClientIdentifier Other =
        ClientIdentifier.ForCimd("https://chatgpt.com/oauth/client.json");

    private static readonly SubjectId Ada = SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0XY");

    private static readonly SubjectId Grace = SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0ZZ");

    private const string Mcp = "https://mcp.example.com/mcp";

    private const string Reader = "https://reader.example.com/api";

    /// <summary>
    /// Consent that was never given is <see langword="null"/>, not an empty record.
    /// </summary>
    [Fact]
    public async Task Consent_that_was_never_given_is_not_found()
    {
        var store = NewConsentStore();

        Assert.Null(await store.FindAsync(Ada, Claude, CancellationToken.None));
    }

    /// <summary>
    /// A grant reads back with its scope, its resources and the instant the caller supplied.
    /// </summary>
    /// <remarks>
    /// <c>GrantedAt</c> is the moment passed in rather than one the store took for itself, so two
    /// implementations do not date the same approval differently.
    /// </remarks>
    [Fact]
    public async Task Consent_is_found_after_it_is_granted()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewConsentStore();

        await store.GrantAsync(Ada, Claude, ScopeSet.FromStorage("story:read"), [Mcp], now, CancellationToken.None);

        var found = await store.FindAsync(Ada, Claude, CancellationToken.None);

        Assert.NotNull(found);
        Assert.True(found.Scope.Contains("story:read"));
        Assert.Equal([Mcp], found.Resources);
        Assert.Equal(now, found.GrantedAt);
    }

    /// <summary>
    /// C-24: a second grant leaves the union of both scopes and both resources, not the newer pair.
    /// </summary>
    [Fact]
    public async Task A_second_grant_widens_rather_than_replaces()
    {
        // C-24, and the whole reason this interface has a GrantAsync rather than a StoreAsync. A
        // store that assigns the new record keeps only `story:write` here, so the client's next call
        // on `story:read` — a scope the user approved and never withdrew — is refused.
        var now = DateTimeOffset.UtcNow;
        var store = NewConsentStore();

        await store.GrantAsync(Ada, Claude, ScopeSet.FromStorage("story:read"), [Mcp], now, CancellationToken.None);
        await store.GrantAsync(
            Ada, Claude, ScopeSet.FromStorage("story:write"), [Reader], now.AddMinutes(1), CancellationToken.None);

        var found = await store.FindAsync(Ada, Claude, CancellationToken.None);

        Assert.NotNull(found);
        Assert.True(found.Scope.Contains("story:read"), "the earlier scope was dropped");
        Assert.True(found.Scope.Contains("story:write"), "the newer scope is missing");

        // Resources are the RFC 8707 grant set and widen the same way: a token request may narrow to
        // one of these and may never widen beyond them, so dropping one revokes an audience.
        Assert.Contains(Mcp, found.Resources);
        Assert.Contains(Reader, found.Resources);
    }

    /// <summary>
    /// Granting what is already held leaves one scope and one resource rather than two of each.
    /// </summary>
    /// <remarks>
    /// The other half of C-24: a union written as concatenation passes the widening test above and is
    /// still wrong.
    /// </remarks>
    [Fact]
    public async Task Re_granting_the_same_scope_does_not_duplicate_it()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewConsentStore();

        await store.GrantAsync(Ada, Claude, ScopeSet.FromStorage("story:read"), [Mcp], now, CancellationToken.None);
        await store.GrantAsync(
            Ada, Claude, ScopeSet.FromStorage("story:read"), [Mcp], now.AddMinutes(1), CancellationToken.None);

        var found = await store.FindAsync(Ada, Claude, CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal(["story:read"], found.Scope.Values);
        Assert.Equal([Mcp], found.Resources);
    }

    /// <summary>
    /// One approval answers for that subject and that client only — another client finds nothing, and
    /// so does another subject.
    /// </summary>
    [Fact]
    public async Task Consent_is_per_user_and_per_client()
    {
        // Both halves of the key, checked in both directions. A store keyed on the subject alone
        // would hand one client the consent another client was granted.
        var now = DateTimeOffset.UtcNow;
        var store = NewConsentStore();

        await store.GrantAsync(Ada, Claude, ScopeSet.FromStorage("story:read"), [Mcp], now, CancellationToken.None);

        Assert.Null(await store.FindAsync(Ada, Other, CancellationToken.None));
        Assert.Null(await store.FindAsync(Grace, Claude, CancellationToken.None));
    }

    /// <summary>
    /// Withdrawal removes the record and answers <see langword="true"/> once; a repeat, and a
    /// withdrawal of something never granted, both answer <see langword="false"/>.
    /// </summary>
    [Fact]
    public async Task Withdrawing_consent_removes_it_and_says_whether_it_did()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewConsentStore();

        await store.GrantAsync(Ada, Claude, ScopeSet.FromStorage("story:read"), [Mcp], now, CancellationToken.None);

        Assert.True(await store.RevokeAsync(Ada, Claude, CancellationToken.None));
        Assert.Null(await store.FindAsync(Ada, Claude, CancellationToken.None));

        // A second withdrawal is not a second event, and withdrawing something that was never
        // granted is observable rather than a silent success.
        Assert.False(await store.RevokeAsync(Ada, Claude, CancellationToken.None));
        Assert.False(await store.RevokeAsync(Grace, Other, CancellationToken.None));
    }

    /// <summary>
    /// E-37: the list holds one record per client this subject approved, and nobody else's.
    /// </summary>
    [Fact]
    public async Task Listing_returns_one_record_per_client_for_that_subject_only()
    {
        // E-37, and the reason it has to exist: consent is remembered so a returning client need
        // not ask again, which means an approval given once is invisible from then on. RevokeAsync
        // needs a client id, and the whole reason to call it is that you no longer remember which
        // ones there are.
        var now = DateTimeOffset.UtcNow;
        var store = NewConsentStore();

        await store.GrantAsync(Ada, Claude, ScopeSet.FromStorage("story:read"), [Mcp], now, CancellationToken.None);
        await store.GrantAsync(Ada, Other, ScopeSet.FromStorage("story:write"), [Reader], now, CancellationToken.None);
        await store.GrantAsync(Grace, Claude, ScopeSet.FromStorage("story:read"), [Mcp], now, CancellationToken.None);

        var listed = await store.ListAsync(Ada, CancellationToken.None);

        // Ordinal order, so `chatgpt.com` precedes `claude.ai`. Sorted rather than taken as the
        // store returned it: the contract promises newest first, and these three were granted at
        // one timestamp, so any order is conforming and asserting one would pin an implementation
        // detail rather than the rule.
        Assert.Equal(
            [Other.Value, Claude.Value],
            listed.Select(c => c.ClientId.Value).OrderBy(v => v, StringComparer.Ordinal));

        // Grace's approval of the same client is hers. This feeds a page a person reads to decide
        // what to withdraw, so a stranger's row here is somebody withdrawing the wrong thing.
        Assert.Equal(
            [Claude.Value],
            (await store.ListAsync(Grace, CancellationToken.None)).Select(c => c.ClientId.Value));
    }

    /// <summary>
    /// A widened approval is one row carrying both scopes and both resources, not two rows.
    /// </summary>
    [Fact]
    public async Task Listing_reflects_a_widening_rather_than_showing_two_rows()
    {
        // The same C-24 rule the rest of this file is about, asked of the list: a client that comes
        // back for one more scope is still one approval, and the record shows the union. Two rows
        // here would mean a person could withdraw one and believe they were done.
        var now = DateTimeOffset.UtcNow;
        var store = NewConsentStore();

        await store.GrantAsync(Ada, Claude, ScopeSet.FromStorage("story:read"), [Mcp], now, CancellationToken.None);
        await store.GrantAsync(Ada, Claude, ScopeSet.FromStorage("story:write"), [Reader], now, CancellationToken.None);

        var record = Assert.Single(await store.ListAsync(Ada, CancellationToken.None));

        Assert.Equal(["story:read", "story:write"], record.Scope.Values.OrderBy(v => v, StringComparer.Ordinal));
        Assert.Equal([Mcp, Reader], record.Resources.OrderBy(v => v, StringComparer.Ordinal));
    }

    /// <summary>A subject who has approved nothing lists empty rather than failing.</summary>
    [Fact]
    public async Task Listing_for_a_subject_who_has_approved_nothing_is_empty()
    {
        var store = NewConsentStore();

        Assert.Empty(await store.ListAsync(Ada, CancellationToken.None));
    }

    /// <summary>
    /// A withdrawn approval is gone from the list, and the approval beside it is still on it.
    /// </summary>
    [Fact]
    public async Task A_withdrawn_approval_leaves_the_list()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewConsentStore();

        await store.GrantAsync(Ada, Claude, ScopeSet.FromStorage("story:read"), [Mcp], now, CancellationToken.None);
        await store.GrantAsync(Ada, Other, ScopeSet.FromStorage("story:read"), [Mcp], now, CancellationToken.None);

        Assert.True(await store.RevokeAsync(Ada, Claude, CancellationToken.None));

        Assert.Equal(
            [Other.Value],
            (await store.ListAsync(Ada, CancellationToken.None)).Select(c => c.ClientId.Value));
    }

    /// <summary>
    /// Withdrawing one client's consent leaves another client's, asked of the lookup rather than the
    /// list.
    /// </summary>
    [Fact]
    public async Task Withdrawing_one_client_leaves_another_granted()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewConsentStore();

        await store.GrantAsync(Ada, Claude, ScopeSet.FromStorage("story:read"), [Mcp], now, CancellationToken.None);
        await store.GrantAsync(Ada, Other, ScopeSet.FromStorage("story:read"), [Mcp], now, CancellationToken.None);

        Assert.True(await store.RevokeAsync(Ada, Claude, CancellationToken.None));

        Assert.NotNull(await store.FindAsync(Ada, Other, CancellationToken.None));
    }
}
