using System.Security.Claims;
using Boltway.Mcp;
using Xunit;

namespace Boltway.Mcp.Tests;

/// <summary>
/// What <see cref="ResourceServerAuthenticator.FromClaims"/> reads out of a validated token.
/// </summary>
/// <remarks>
/// The half that had to move when the authorization server let an account hold several roles. Its
/// <c>IUserStore</c> carried one for a year precisely because this read the claim with
/// <c>FindFirst</c>, and storing a set there would have produced tokens whose second and third roles
/// were dropped here, silently, on the surface furthest from anybody who could notice.
/// </remarks>
public sealed class ResourceServerClaimsTests
{
    private static CallerPrincipal Read(params Claim[] claims) =>
        ResourceServerAuthenticator.FromClaims().Map(
            new ClaimsPrincipal(new ClaimsIdentity(claims, "test")));

    /// <summary>Every role travels, not the first.</summary>
    [Fact]
    public void All_of_the_roles_are_read()
    {
        var caller = Read(
            new Claim("sub", "01ABC"),
            new Claim("role", "founder"),
            new Claim("role", "editor"));

        Assert.Equal(["founder", "editor"], caller.Roles);
    }

    /// <summary>One role is still one role, and arrives as a list of one.</summary>
    [Fact]
    public void A_single_role_is_a_list_of_one()
    {
        Assert.Equal(["founder"], Read(new Claim("sub", "01ABC"), new Claim("role", "founder")).Roles);
    }

    /// <summary>
    /// No role claim means the caller holds none, and this library does not invent one.
    /// </summary>
    /// <remarks>
    /// It used to answer <c>user</c>, which was a vocabulary — a word no deployment had chosen,
    /// arriving from a library that documents everywhere else that it holds no opinion about what a
    /// role is. What an absent role means is the connector's decision, and a connector that wants a
    /// floor writes one.
    /// </remarks>
    [Fact]
    public void An_absent_role_claim_is_no_roles_rather_than_a_default()
    {
        Assert.Empty(Read(new Claim("sub", "01ABC")).Roles);
    }

    /// <summary>The granted scopes travel, so a connector can gate a tool on one.</summary>
    [Fact]
    public void Scopes_are_read_off_the_token()
    {
        var caller = Read(new Claim("sub", "01ABC"), new Claim("scope", "openid email kb:read kb:write"));

        Assert.Equal(
            ["email", "kb:read", "kb:write", "openid"],
            caller.Scopes.OrderBy(s => s, StringComparer.Ordinal).ToList());
    }

    /// <summary>
    /// No scope claim is the empty set, and a connector reading it has to fall back rather than
    /// refuse: the static-token path has no authorization server and so never carries one.
    /// </summary>
    [Fact]
    public void No_scope_claim_is_empty_rather_than_a_refusal()
    {
        Assert.Empty(Read(new Claim("sub", "01ABC"), new Claim("role", "founder")).Scopes);
    }

    /// <summary>
    /// A claim that is not a valid scope string yields nothing rather than throwing. The token has
    /// already validated; this read decides how much authority it carries, and the safe direction
    /// to be wrong in is less.
    /// </summary>
    [Fact]
    public void A_malformed_scope_claim_grants_nothing()
    {
        Assert.Empty(Read(new Claim("sub", "01ABC"), new Claim("scope", "kb:read \"quoted\"")).Scopes);
    }

    /// <summary>Permissions arrive space-separated, the same shape as `scope`.</summary>
    [Fact]
    public void Permissions_are_split_on_spaces()
    {
        var caller = Read(
            new Claim("sub", "01ABC"),
            new Claim("role", "founder"),
            new Claim("permissions", "read_kb  write_kb read_ledgers "));

        Assert.Equal(
            ["read_kb", "read_ledgers", "write_kb"],
            caller.Permissions.OrderBy(p => p, StringComparer.Ordinal).ToList());
    }

    /// <summary>
    /// No permissions claim is "the server does not publish them", not "this caller holds none".
    /// </summary>
    /// <remarks>
    /// The difference decides whether a connector with its own role table falls back to it or
    /// refuses everything. Treating empty as a refusal would break every connector the day it
    /// pointed at a server that resolves nothing into its tokens.
    /// </remarks>
    [Fact]
    public void An_absent_permissions_claim_is_empty_rather_than_a_refusal()
    {
        var caller = Read(new Claim("sub", "01ABC"), new Claim("role", "founder"));

        Assert.Empty(caller.Permissions);
        Assert.Equal(["founder"], caller.Roles);
    }
}
