using Boltway.AuthorizationServer.Abstractions.Tokens;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Token;

/// <summary>
/// Puts the account's handle and role, and its email when the grant covers it, into the access
/// token.
///
/// <para>
/// Registered only when a deployment asks for it. The default remains a token that says
/// nothing about the subject beyond its identifier, because every claim released is a claim
/// every resource server holding that token can read, and a server that only needs to know
/// <em>that</em> a request is authorised should not be handed a name and an address.
/// </para>
///
/// <para>
/// <c>email</c> is released only when the grant includes the <c>email</c> scope. It is a
/// separate scope in OIDC for exactly this reason, and a consent screen that said
/// <em>Confirm who you are</em> should not be the one that hands over an address. The handle
/// goes out unconditionally: it is the pseudonym the subject chose, it is what an audit trail
/// needs to be readable, and it is already the thing the sign-in page showed them.
/// </para>
///
/// <para>
/// It cannot overwrite a protocol claim. <c>JwtTokenMinter</c> refuses that with an
/// exception rather than a silent skip, which is what stops this interface from being an
/// escalation seam - a mapper able to set <c>sub</c> or <c>scope</c> would be one.
/// </para>
/// </summary>
public sealed class UserAccountClaims(IUserStore users, IRoleStore roles) : IAccessTokenClaims
{
    private readonly IUserStore _users = users ?? throw new ArgumentNullException(nameof(users));
    private readonly IRoleStore _roles = roles ?? throw new ArgumentNullException(nameof(roles));

    /// <inheritdoc />
    public async ValueTask<IReadOnlyDictionary<string, object?>> ForAsync(
        SubjectId subject, ScopeSet scope, CancellationToken ct = default)
    {
        var account = await _users.FindBySubjectAsync(subject, ct);

        // Not an error. A grant can outlive the account it was issued for - a user deleted
        // between sign-in and refresh - and failing the token exchange here would turn a
        // tidy-up into an outage on a path that has nothing to do with the deletion. The token
        // is still valid for what it says; it just says less.
        if (account is null) return Empty;

        var claims = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["preferred_username"] = account.Username,
        };

        if (account.Email is { Length: > 0 } email && scope.Contains("email"))
        {
            claims["email"] = email;

            // Shipped alongside, never alone: `email_verified` absent reads as false to some
            // clients and as unknown to others, and a resource server deciding anything on an
            // address wants to know which it is looking at.
            claims["email_verified"] = account.EmailVerified;
        }

        // Not gated on a scope, unlike email, and the asymmetry is the point. `email` is personal
        // data the subject consents to release; a role is what the resource server needs in order
        // to answer at all. Putting it behind a scope would mean a client that forgot to ask gets a
        // token that authenticates fine and then reads nothing, which surfaces as an empty
        // result set rather than as a missing scope.
        //
        // Only in the access token. The wiring passes this mapper's output to the access-token
        // descriptor and deliberately not to the ID token: the ID token is the client's proof of
        // who signed in, and a client has no business routing on somebody's role.
        if (account.Roles.Count > 0)
        {
            // An array, and one role does not collapse it to a string. A consumer branching on the
            // JSON type to read a claim is one that reads it wrong the day somebody is given a
            // second role - and that day is invisible from here.
            claims["role"] = account.Roles;

            // What the roles stand for, resolved here so the resource server does not have to ask.
            // Space-separated, the same shape as `scope`, because it is the same kind of thing: a
            // set of short tokens a server checks membership in.
            //
            // Roles the realm no longer defines resolve to nothing rather than failing the mint -
            // the same decision this mapper already makes for an account deleted mid-grant, and the
            // case a restore from an older backup produces. The account signs in holding less.
            var definitions = await _roles
                .FindManyAsync(account.Realm, account.Roles.ToList(), ct)
                .ConfigureAwait(false);

            var permissions = definitions
                .SelectMany(d => d.Permissions)
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToList();

            if (permissions.Count > 0)
            {
                claims["permissions"] = string.Join(' ', permissions);
            }
        }

        return claims;
    }

    private static readonly IReadOnlyDictionary<string, object?> Empty =
        new Dictionary<string, object?>(StringComparer.Ordinal);
}
