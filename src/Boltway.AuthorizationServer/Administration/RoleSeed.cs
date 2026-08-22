namespace Boltway.AuthorizationServer.Administration;

/// <summary>
/// A role a deployment declares should exist.
/// </summary>
/// <remarks>
/// <para>
/// The declarative half of <see cref="UserAdministration.SeedRolesAsync"/>: what a fresh directory
/// starts with, so that standing one up is a migration rather than a checklist. The vocabulary in
/// it — ids, permission names — belongs to the deployment and its resource servers; this library
/// stores the strings and never interprets them, the same rule <c>RoleDefinition</c> states.
/// </para>
/// <para>
/// A seed is a floor, not an assertion. It says "this role exists"; it does not say "this role
/// still means what the seed says", because after bootstrap the definitions belong to the admin
/// surface and a deploy must not quietly revert an edit somebody made there.
/// </para>
/// </remarks>
/// <param name="Id">The immutable id a token will carry. Matched ordinally, chosen once.</param>
/// <param name="Name">What a person reads, defaulting to the id — free to be reworded later.</param>
/// <param name="Permissions">
/// What the role stands for, in the resource server's vocabulary. Null and empty both mean a role
/// that stands for nothing yet, which is a legitimate thing to define.
/// </param>
public sealed record RoleSeed(
    string Id, string? Name = null, IReadOnlyList<string>? Permissions = null);

/// <summary>What seeding did about one declared role.</summary>
/// <param name="Id">The role.</param>
/// <param name="Created">
/// <see langword="true"/> when the definition was written; <see langword="false"/> when one already
/// existed and was left exactly as it was.
/// </param>
public sealed record SeededRole(string Id, bool Created);
