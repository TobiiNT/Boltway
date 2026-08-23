using System.Collections.Frozen;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Administration;

/// <summary>
/// Withholds the administrative scopes — <see cref="AdminScopes.Administrative"/>, the users pair
/// and the roles pair alike — from accounts whose role is not one this deployment named.
/// </summary>
/// <remarks>
/// <para>
/// <b>Without this, turning on the admin API makes every account that can sign in an
/// administrator.</b> <c>AdminAuthorization.Check</c> asks two questions — is the principal a
/// bearer rather than a cookie (<c>N-17</c>), and does the token carry the scope — and deliberately
/// never reads the role: the remarks on <see cref="AdminScopes"/> say the role "stays an opaque
/// string it never compares to a constant, and turning a role into an entitlement is
/// <c>IScopeEntitlementPolicy</c>'s job, in the deployment". That is the correct division. What was
/// missing is that no deployment had anything to compose there, so every one of them ran the
/// permissive default, and the answer to "who may administer the directory" was "anyone with a
/// password".
/// </para>
/// <para>
/// Measured on a running deployment: the admin UI asks for <c>openid users:read users:write</c>, and
/// an administrator's account and a would-be test account are offered exactly the same consent screen.
/// </para>
/// <para>
/// <b>The role names come from the deployment and the mechanism from here.</b> This class holds no
/// constant a role is compared against — <c>admin</c>, <c>founder</c> and <c>owner</c> are all
/// somebody's vocabulary and none of them are this library's.
/// </para>
/// <para>
/// <b>It narrows rather than refusing outright.</b> A request for <c>openid users:read</c> from an
/// ordinary account yields <c>openid</c>, so they sign in, and the consent screen they are shown
/// lists what they are actually getting — a person who cannot administer the directory is told by
/// the absence of those lines, before they agree to anything. Returning the empty set instead would
/// refuse the whole authorization with <c>invalid_scope</c>, which reads to a client as "this server
/// is broken" rather than "you are not an administrator". The subsequent <c>401</c> from
/// <c>/admin/*</c> carries <c>insufficient_scope</c>, which is the same fact stated again at the
/// place it applies.
/// </para>
/// <para>
/// <see cref="AdminScopes.Self"/> is deliberately not gated. It is the scope for acting on your own
/// account and nobody else's, so gating it on an administrative role would be backwards.
/// </para>
/// <para>
/// The roles pair is gated exactly as hard as the users pair, and <see
/// cref="AdminScopes.Administrative"/> is what keeps that true by construction: a scope added there
/// is stripped here without this class changing. <c>roles:write</c> in particular is not a lesser
/// grant — redefining what a role stands for changes what every holder's next token may do, so a
/// policy that stripped only the users pair would leave the vocabulary those scopes protect
/// writable by anyone who could consent.
/// </para>
/// </remarks>
public sealed class AdminRoleScopePolicy : IScopeEntitlementPolicy
{
    private readonly FrozenSet<string> _roles;

    /// <summary>Name the roles that may hold the administrative scopes.</summary>
    /// <param name="roles">
    /// Role strings, compared ordinally and exactly. Ordinal because every other identifier
    /// comparison in this tree is, and exactly because a role is data somebody typed into an
    /// account: matching <c>Founder</c> against <c>founder</c> would make the directory's own
    /// contents ambiguous.
    /// </param>
    /// <exception cref="ArgumentException">
    /// No roles were named. An empty set would withhold the administrative scopes from everybody,
    /// which locks the deployment out of its own directory — and it would do it quietly, on the
    /// next sign-in, long after whoever wrote the empty value had stopped watching.
    /// </exception>
    public AdminRoleScopePolicy(IEnumerable<string> roles)
    {
        ArgumentNullException.ThrowIfNull(roles);

        _roles = roles
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Select(r => r.Trim())
            .ToFrozenSet(StringComparer.Ordinal);

        if (_roles.Count == 0)
        {
            throw new ArgumentException(
                "No administrative roles were named, so no account could ever hold "
                + string.Join(", ", AdminScopes.Administrative.Select(s => $"`{s}`"))
                + " and the directory would have no administrator.",
                nameof(roles));
        }
    }

    /// <summary>The roles that may hold the administrative scopes.</summary>
    public IReadOnlySet<string> Roles => _roles;

    /// <inheritdoc />
    public ValueTask<ScopeSet> FilterAsync(
        UserAccount user, ScopeSet requested, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);

        // The overwhelmingly common request — a connector asking for its own scopes — never
        // mentions these, and leaves here having allocated almost nothing.
        if (!AdminScopes.Administrative.Any(requested.Contains))
        {
            return ValueTask.FromResult(requested);
        }

        // Any one of them is enough, and reading only the first would be a privilege bug rather
        // than a narrowing: an account given `editor` before `founder` would be refused the scopes
        // its second role grants, and the refusal would look like the policy working.
        if (user.Roles.Any(_roles.Contains))
        {
            return ValueTask.FromResult(requested);
        }

        // Re-parsed rather than constructed: ScopeSet's constructor is private, and every token
        // here came out of one, so this cannot fail. The discard is the honest way to say so.
        var kept = requested.Values.Where(NotAdministrative);

        _ = ScopeSet.TryParse(string.Join(' ', kept), out var narrowed, out _);

        return ValueTask.FromResult(narrowed);

        static bool NotAdministrative(string scope) =>
            !AdminScopes.Administrative.Contains(scope, StringComparer.Ordinal);
    }
}
