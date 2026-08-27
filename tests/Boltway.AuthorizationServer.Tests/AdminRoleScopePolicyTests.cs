using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Administration;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Who may hold <c>users:read</c> and <c>users:write</c>.
/// </summary>
/// <remarks>
/// The gap these cover was live rather than hypothetical: with the permissive default registered
/// and nothing composed over it, every account that could sign in was offered the administrative
/// scopes on the consent screen and could have used them.
/// </remarks>
public sealed class AdminRoleScopePolicyTests
{
    private static readonly AdminRoleScopePolicy Policy = new(["founder"]);

    private static UserAccount Account(string? role) =>
        new(
            SubjectId.FromStorage("01KZAWCB5XY91G8N9XG84WR1EN"),
            Username: "someone",
            Email: null,
            EmailVerified: false,
            PasswordHash: null,
            DisabledAt: null) { Roles = role is null ? [] : [role] };

    private static ScopeSet Parse(string raw)
    {
        Assert.True(ScopeSet.TryParse(raw, out var scopes, out _));
        return scopes;
    }

    [Fact]
    public async Task A_named_role_keeps_the_administrative_scopes()
    {
        var granted = await Policy.FilterAsync(
            Account("founder"), Parse("openid users:read users:write"), CancellationToken.None);

        Assert.True(granted.Contains("users:read"));
        Assert.True(granted.Contains("users:write"));
        Assert.True(granted.Contains("openid"));
    }

    /// <summary>
    /// The case this class exists for.
    /// </summary>
    /// <remarks>
    /// The roles below are deliberately ordinary ones - the kind a deployment hands to most of its
    /// directory. A policy tested only against obviously-wrong roles passes and still leaves
    /// `users:write` with everybody who was given a plausible one.
    /// </remarks>
    [Theory]
    [InlineData("employee")]
    [InlineData("contractor")]
    [InlineData("Founder")]  // ordinal and exact: a near-miss is a miss.
    [InlineData("")]
    [InlineData(null)]
    public async Task Any_other_role_loses_them_and_keeps_the_rest(string? role)
    {
        var granted = await Policy.FilterAsync(
            Account(role), Parse("openid users:read users:write"), CancellationToken.None);

        Assert.False(granted.Contains("users:read"));
        Assert.False(granted.Contains("users:write"));

        // Narrowed, not refused. An empty set becomes `invalid_scope`, which reads to a client as a
        // broken server rather than as "you are not an administrator".
        Assert.True(granted.Contains("openid"));
    }

    /// <summary>
    /// The roles pair is gated exactly like the users pair, and losing it costs nothing else.
    /// </summary>
    /// <remarks>
    /// <c>roles:write</c> redefines what every holder of a role may do, so it is an administrative
    /// scope in full standing - a policy that stripped only the users pair would let any account
    /// consent its way into rewriting the vocabulary the users pair protects.
    /// </remarks>
    [Fact]
    public async Task The_roles_pair_is_withheld_like_the_users_pair()
    {
        var granted = await Policy.FilterAsync(
            Account("employee"), Parse("openid roles:read roles:write"), CancellationToken.None);

        Assert.False(granted.Contains("roles:read"));
        Assert.False(granted.Contains("roles:write"));
        Assert.True(granted.Contains("openid"));
    }

    [Fact]
    public async Task A_named_role_keeps_the_roles_pair()
    {
        var granted = await Policy.FilterAsync(
            Account("founder"), Parse("openid roles:read roles:write"), CancellationToken.None);

        Assert.True(granted.Contains("roles:read"));
        Assert.True(granted.Contains("roles:write"));
    }

    /// <summary>
    /// <c>users:self</c> is a person acting on their own account, so an administrative role is not
    /// what qualifies them for it.
    /// </summary>
    [Fact]
    public async Task Self_service_is_not_gated()
    {
        var granted = await Policy.FilterAsync(
            Account("employee"), Parse("openid users:self"), CancellationToken.None);

        Assert.True(granted.Contains("users:self"));
    }

    /// <summary>
    /// A connector's own request is returned unchanged, and identically.
    /// </summary>
    [Fact]
    public async Task A_request_that_names_no_administrative_scope_is_untouched()
    {
        var requested = Parse("openid docs:read docs:write email offline_access");

        var granted = await Policy.FilterAsync(
            Account("employee"), requested, CancellationToken.None);

        Assert.Equal(requested, granted);
    }

    /// <summary>
    /// Naming no roles is refused where it is written, not discovered at the next sign-in.
    /// </summary>
    /// <remarks>
    /// An empty set withholds the administrative scopes from everybody, which is a deployment locked
    /// out of its own directory - and quietly, because nothing fails until somebody tries to sign
    /// in to the admin UI and is simply not granted anything.
    /// </remarks>
    [Fact]
    public void Naming_no_roles_is_refused_at_construction()
    {
        Assert.Throws<ArgumentException>(() => new AdminRoleScopePolicy([]));
        Assert.Throws<ArgumentException>(() => new AdminRoleScopePolicy(["", "   "]));
    }
}
