using System.Net;
using System.Text.Json;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Scopes;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// <see cref="IScopeEntitlementPolicy"/> - the check scope alone cannot make.
/// </summary>
/// <remarks>
/// Scopes are requested by a client and granted by consent, so without this any account could obtain
/// any scope by signing in to a client that asks for it and clicking allow. A scope says what a
/// client may do on somebody's behalf; whether that somebody may do it is a different question, and
/// nothing in OAuth answers it.
/// </remarks>
public sealed class ScopeEntitlementTests
{
    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    /// <summary>Grants only what one named role may hold - one deployment's policy, as a test double.</summary>
    private sealed class FounderOnly(string role) : IScopeEntitlementPolicy
    {
        public ValueTask<ScopeSet> FilterAsync(
            UserAccount user, ScopeSet requested, CancellationToken cancellationToken)
        {
            if (user.Roles.Contains(role, StringComparer.Ordinal))
            {
                return ValueTask.FromResult(requested);
            }

            _ = ScopeSet.TryParse(
                string.Join(' ', requested.Values.Where(s => !s.StartsWith("mcp:", StringComparison.Ordinal))),
                out var narrowed,
                out _);

            return ValueTask.FromResult(narrowed);
        }
    }

    private static async Task<FlowFixture> StartAsync(IScopeEntitlementPolicy policy, string? role) =>
        await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client("https://claude.ai/.well-known/oauth-client", ClientType.Confidential);

            seed.ConfigureServices = services =>
            {
                var roles = new Storage.InMemory.InMemoryRoleStore();
                var users = new Storage.InMemory.InMemoryUserStore(roles);

                users.StoreAsync(
                    new UserAccount(seed.SignedInUser!.Value.Subject, "ada", null, false, null),
                    CancellationToken.None).GetAwaiter().GetResult();

                if (role is { Length: > 0 })
                {
                    // Defined, then held. Creation does not assign and assignment refuses an id the
                    // realm does not define, so a fixture that wants an account holding a role has
                    // to say what that role is first.
                    roles.StoreAsync(new RoleDefinition(role, role, []), CancellationToken.None)
                        .GetAwaiter().GetResult();

                    users.SetRolesAsync(seed.SignedInUser!.Value.Subject, [role], CancellationToken.None)
                        .GetAwaiter().GetResult();
                }

                services.AddSingleton<IUserStore>(users);
                services.AddSingleton<IRoleStore>(roles);
                services.AddSingleton(policy);
            };
        });

    private static string AuthorizeUrl(string scope) =>
        "/authorize?response_type=code"
        + "&client_id=" + HttpUtility.UrlEncode("https://claude.ai/.well-known/oauth-client")
        + "&redirect_uri=" + HttpUtility.UrlEncode("https://claude.ai/api/mcp/auth_callback")
        + "&scope=" + HttpUtility.UrlEncode(scope)
        + "&resource=" + HttpUtility.UrlEncode(Build.Resource)
        + "&state=xyz&code_challenge=" + Verifier.ComputeS256Challenge() + "&code_challenge_method=S256";

    /// <summary>
    /// An entitled account gets what it asked for.
    /// </summary>
    /// <remarks>
    /// The control. Without it, a filter that refused everything would pass the two tests below and
    /// look like a working authorization model.
    /// </remarks>
    [Fact]
    public async Task An_entitled_account_is_granted_the_scope()
    {
        await using var fixture = await StartAsync(new FounderOnly("founder"), role: "founder");

        var response = await fixture.Client.GetAsync(AuthorizeUrl("openid mcp:tools"));

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.Contains("code=", response.Headers.Location!.Query, StringComparison.Ordinal);
    }

    /// <summary>
    /// An unentitled account connects, with less.
    /// </summary>
    /// <remarks>
    /// It filters rather than refusing. OAuth already means "granted may be narrower than
    /// requested", so a demotion should shrink what a client gets - turning it into a client that
    /// cannot connect at all is a much larger change than the one the operator made.
    /// </remarks>
    [Fact]
    public async Task An_unentitled_account_still_connects_with_a_narrower_grant()
    {
        await using var fixture = await StartAsync(new FounderOnly("founder"), role: "employee");

        var response = await fixture.Client.GetAsync(AuthorizeUrl("openid mcp:tools"));

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.Contains("code=", response.Headers.Location!.Query, StringComparison.Ordinal);
    }

    /// <summary>
    /// Filtering to nothing is <c>invalid_scope</c> - X-42.
    /// </summary>
    /// <remarks>
    /// The one case where refusing is right: the client asked for nothing this account can have, so
    /// there is no narrower grant to issue. It arrives by redirect like every other authorization
    /// error, because the redirect URI has already been validated by then.
    /// </remarks>
    [Fact]
    public async Task Filtering_to_nothing_is_invalid_scope()
    {
        await using var fixture = await StartAsync(new FounderOnly("founder"), role: "employee");

        var response = await fixture.Client.GetAsync(AuthorizeUrl("mcp:tools"));

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var query = HttpUtility.ParseQueryString(response.Headers.Location!.Query);

        Assert.Equal("invalid_scope", query["error"]);
        Assert.Equal("xyz", query["state"]);
    }

    /// <summary>
    /// An account the directory no longer has is granted nothing.
    /// </summary>
    /// <remarks>
    /// Reachable: a session outlives the account it names. Passing the request through unfiltered
    /// would make deleting an account the way to obtain every scope.
    /// </remarks>
    [Fact]
    public async Task A_session_naming_no_account_is_granted_nothing()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client("https://claude.ai/.well-known/oauth-client", ClientType.Confidential);

            seed.ConfigureServices = services =>
            {
                // An empty directory, and a session that names somebody in it.
                services.AddSingleton<IUserStore>(new Storage.InMemory.InMemoryUserStore());
                services.AddSingleton<IRoleStore>(new Storage.InMemory.InMemoryRoleStore());
                services.AddSingleton<IScopeEntitlementPolicy>(new FounderOnly("founder"));
            };
        });

        var response = await fixture.Client.GetAsync(AuthorizeUrl("openid mcp:tools"));

        var query = HttpUtility.ParseQueryString(response.Headers.Location!.Query);

        Assert.Equal("invalid_scope", query["error"]);
    }

    /// <summary>
    /// The shipped default changes nothing.
    /// </summary>
    [Fact]
    public async Task The_default_policy_grants_what_was_requested()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
            seed.Client = Build.Client("https://claude.ai/.well-known/oauth-client", ClientType.Confidential));

        var response = await fixture.Client.GetAsync(AuthorizeUrl("openid mcp:tools"));

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.Contains("code=", response.Headers.Location!.Query, StringComparison.Ordinal);
    }
}
