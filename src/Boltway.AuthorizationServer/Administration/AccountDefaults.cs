namespace Boltway.AuthorizationServer.Administration;

/// <summary>
/// The roles a new account holds when its creator names none.
/// </summary>
/// <remarks>
/// <para>
/// An account created without a role signs in and holds nothing, and the person who discovers that
/// is never the operator who forgot the argument — it is the account's owner, later, reading an
/// almost-empty resource as data loss. A deployment that wants "everyone starts as a member" says
/// so once, here, instead of relying on every creation path to remember.
/// </para>
/// <para>
/// <b>These fill an absence; they never add to a choice.</b> A caller who names a role gets exactly
/// that role — <see cref="UserAdministration.CreateAsync"/> does not union the defaults in, because
/// an assignment the operator did not make and cannot see in their own request is how an account
/// ends up holding more than anyone decided it should.
/// </para>
/// <para>
/// <b>Registering this type is the whole switch.</b> Absent, creation behaves as it always has —
/// no role unless one is named. There is deliberately no way to construct an empty one: "no
/// defaults" is said by not registering it, so an empty set can only be a configuration mistake,
/// and it is refused here rather than discovered as accounts that hold nothing.
/// </para>
/// <para>
/// Every id must be one the realm defines by the time an account is created —
/// <c>IUserStore.SetRolesAsync</c> refuses an assignment nothing can resolve, which turns a typo
/// here into a failed creation rather than a silent no-op. The host's <c>migrate</c> verb checks
/// this at deploy time, after seeding, so the failure lands in a deploy log instead of on the
/// first sign-up.
/// </para>
/// </remarks>
public sealed record AccountDefaults
{
    /// <summary>Declare what a new account holds when its creator names nothing.</summary>
    /// <param name="roles">
    /// Role ids, matched ordinally against the realm's definitions. At least one; none may be blank
    /// or carry whitespace, for the same reason <see cref="Abstractions.Users.RoleDefinition"/>
    /// refuses them — they are compared character for character against a claim.
    /// </param>
    /// <exception cref="ArgumentException">The rules above are broken.</exception>
    public AccountDefaults(IEnumerable<string> roles)
    {
        ArgumentNullException.ThrowIfNull(roles);

        var held = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var role in roles)
        {
            if (string.IsNullOrWhiteSpace(role))
            {
                throw new ArgumentException("A default role id cannot be blank.", nameof(roles));
            }

            if (role.Any(char.IsWhiteSpace))
            {
                throw new ArgumentException(
                    $"`{role}` carries whitespace. Role ids are compared ordinally against a claim "
                    + "value, so a space in one is a difference nobody can see.",
                    nameof(roles));
            }

            if (seen.Add(role))
            {
                held.Add(role);
            }
        }

        if (held.Count == 0)
        {
            throw new ArgumentException(
                "No role ids. \"No defaults\" is said by not registering AccountDefaults at all; "
                + "an empty set here can only be a configuration mistake.",
                nameof(roles));
        }

        Roles = held;
    }

    /// <summary>The ids, in the order given, first occurrence winning a duplicate.</summary>
    public IReadOnlyList<string> Roles { get; }
}
