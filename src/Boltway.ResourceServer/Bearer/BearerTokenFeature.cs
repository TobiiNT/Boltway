using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Boltway.ResourceServer.Bearer;

/// <summary>
/// The validated access token, for the endpoint that runs after the middleware.
/// </summary>
/// <remarks>
/// <para>
/// Present on <see cref="HttpContext.Features"/> only when a token validated. There is no "invalid"
/// state to check for, because the middleware never lets an unauthenticated request past a
/// protected endpoint — so a handler that finds this feature knows the token was good, and one that
/// does not find it is on an anonymous endpoint.
/// </para>
/// <para>
/// The scopes are exposed as strings rather than as this server's own identifier types. A resource
/// server's tools compare them against their own constants, and handing out a type that only the
/// authorization server can construct would make the simplest thing a handler does depend on the
/// half of the product it is meant to be deployable without.
/// </para>
/// </remarks>
public sealed class BearerTokenFeature
{
    internal BearerTokenFeature(ClaimsPrincipal principal, IReadOnlyList<string> scopes)
    {
        Principal = principal;
        Scopes = scopes;
    }

    /// <summary>The token's claims.</summary>
    public ClaimsPrincipal Principal { get; }

    /// <summary>The <c>scope</c> claim, split on spaces. Sorted and deduplicated.</summary>
    public IReadOnlyList<string> Scopes { get; }

    /// <summary>Whether the token carries a scope. Ordinal comparison.</summary>
    public bool HasScope(string scope)
    {
        foreach (var granted in Scopes)
        {
            if (string.Equals(granted, scope, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>Reaching the validated token from a handler.</summary>
public static class BearerTokenFeatureExtensions
{
    /// <summary>The validated access token, or <see langword="null"/> on an anonymous endpoint.</summary>
    public static BearerTokenFeature? GetBearerToken(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.Features.Get<BearerTokenFeature>();
    }
}
