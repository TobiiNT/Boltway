using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Requests;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Token;

/// <summary>
/// The <c>client_credentials</c> grant, for a client that acts as an account. RFC 6749 §4.4.
/// </summary>
/// <remarks>
/// <para>
/// <b>This grant exists here in one specific shape: the client names an owner and the token is
/// issued for that account.</b> RFC 6749 §4.4 describes a client acting for itself, and that is the
/// shape this deliberately does not implement — see <c>ReasonCode.ClientHasNoOwner</c>. A token
/// whose <c>sub</c> is a client id resolves against no account, so roles, permissions and anything
/// that attributes a write have nothing to read, and the failure surfaces somewhere else entirely
/// as "this account has no roles".
/// </para>
/// <para>
/// <b>No consent, and that is not a shortcut.</b> Consent records that a user agreed to let a
/// client act for them; here an administrator wrote that agreement down when they set the owner, so
/// there is no second party to ask and no browser to ask in. What replaces it is that setting an
/// owner is an administrative act with an audit row, rather than something a client can do to
/// itself.
/// </para>
/// <para>
/// <b>No refresh token.</b> RFC 6749 §4.4.3 says one SHOULD NOT be included, and the reason applies
/// exactly: the client already holds a credential that mints access tokens whenever it likes, so a
/// refresh token is a second long-lived secret protecting nothing the first does not.
/// </para>
/// <para>
/// <b>Scope comes from the client, never from the request.</b> A <c>scope</c> parameter is refused
/// rather than intersected. Intersection reads as safe and is not: it makes the maximum the thing
/// that is enforced and the request the thing that is audited, so a client asking for less looks
/// identical to one that may only have less. Pinning it on the record means "what may this service
/// account do" is answered by reading the client, in one place, and the answer does not change per
/// request.
/// </para>
/// </remarks>
public sealed class ClientCredentialsGrant(
    IUserStore users,
    IGrantStore grants,
    IResourceRegistry resources,
    TokenIssuer issuer,
    TimeProvider timeProvider,
    IServiceProvider? services = null)
{
    // Optional and last, the same shape RefreshTokenGrant uses, so a host constructing this by
    // hand keeps working. It reaches the entitlement policy and the directory, and a null one
    // means the ceiling is not applied — which is the behaviour every deployment that registers
    // no policy already has, and the registration in AddAuthorizationServer passes it.
    private readonly IServiceProvider _services = services ?? EmptyServices.Instance;

    private readonly IUserStore _users = users ?? throw new ArgumentNullException(nameof(users));
    private readonly IGrantStore _grants = grants ?? throw new ArgumentNullException(nameof(grants));
    private readonly IResourceRegistry _resources = resources ?? throw new ArgumentNullException(nameof(resources));
    private readonly TokenIssuer _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
    private readonly TimeProvider _time = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <summary>Issue an access token for the account this client acts as.</summary>
    public async Task<GrantOutcome> HandleAsync(
        OAuthParameters parameters, ClientRecord client, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(client);

        // The client is already authenticated by the time this runs — TokenEndpoint will not
        // dispatch without it — and it has already been checked against its declared grant types.
        // What is left is whether it is the *kind* of client this grant can serve.
        if (client.Owner is not { } owner)
        {
            return Failed(
                ReasonCode.ClientHasNoOwner,
                OAuthErrorCode.UnauthorizedClient,
                "This client is not registered to act as an account.",
                $"client_id={client.ClientId.Value}");
        }

        // Refused rather than narrowed. The remarks above say why; the practical half is that a
        // client sending `scope` is a client written against a different server's reading of §4.4,
        // and telling it so beats silently issuing something other than what it asked for.
        if (parameters.Contains("scope"))
        {
            return Failed(
                ReasonCode.ScopeNotAllowedForClient,
                OAuthErrorCode.InvalidScope,
                "The 'scope' parameter is not accepted for this grant; scope is fixed on the client.",
                $"client_id={client.ClientId.Value}; permitted={client.AllowedScopes.ToWireString()}");
        }

        if (client.AllowedScopes.IsEmpty)
        {
            // Empty means "whatever the server permits" everywhere else, which is a sensible
            // default for a client a human authorizes and a dangerous one here: there is no human
            // in the loop to see what it turned into. An unscoped service account is a
            // configuration mistake, so it is named rather than resolved to everything.
            return Failed(
                ReasonCode.ScopeNotAllowedForClient,
                OAuthErrorCode.InvalidScope,
                "This client has no scopes, so there is nothing it could be issued a token for.",
                $"client_id={client.ClientId.Value}");
        }

        var account = await _users.FindBySubjectAsync(owner, cancellationToken);

        // One reason for both branches, and the detail is the only place they differ — see
        // ClientOwnerUnusable. A client holding a valid secret is still not entitled to learn
        // whether a particular person's account was deleted or merely suspended.
        if (account is null || !account.IsActive)
        {
            return Failed(
                ReasonCode.ClientOwnerUnusable,
                OAuthErrorCode.InvalidGrant,
                "The account this client acts as cannot be used.",
                $"client_id={client.ClientId.Value}; owner={owner.Value}; "
                + (account is null ? "no such account" : "account disabled"));
        }

        // ───────── the owner's roles are the ceiling, and this is where it is applied ─────────
        //
        // `UserAdministration` says so at the moment a service account is created — "the ceiling is
        // applied when the token is used, by whatever reads its roles" — and the surface that reads
        // this token, `AdminAuthorization`, deliberately never reads the role, which is the correct
        // division. So the ceiling was a sentence true of nowhere: this grant took scope straight
        // off the client record, and a service account owned by an account holding no
        // administrative role was issued `users:write`, read the whole directory including every
        // email, and rewrote it — including promoting its own owner. Measured end to end.
        //
        // /authorize and refresh both filter here already. This is the third caller, and the one
        // whose absence was reachable from a credential rather than from a browser.
        //
        // Refused rather than narrowed, unlike the other two, and the reason is the one this
        // class's own remarks give about the `scope` parameter: a token quietly carrying less than
        // the client record says makes the record the thing that is audited and the token the thing
        // that is enforced. An operator who typed `users:write` would never learn it did not take.
        // A service account whose owner is not entitled is a configuration mistake, and the first
        // moment anything is in a position to say so is right here.
        var entitled = await Authorize.ScopeEntitlement
            .FilterAsync(_services, owner, client.AllowedScopes, cancellationToken)
            .ConfigureAwait(false);

        if (client.AllowedScopes.Values.Any(scope => !entitled.Values.Contains(scope, StringComparer.Ordinal)))
        {
            var withheld = client.AllowedScopes.Values
                .Where(scope => !entitled.Values.Contains(scope, StringComparer.Ordinal));

            return Failed(
                ReasonCode.ScopeNotAllowedForClient,
                OAuthErrorCode.InvalidScope,
                "The account this client acts as is not entitled to every scope the client holds.",
                $"client_id={client.ClientId.Value}; owner={owner.Value}; "
                + $"withheld={string.Join(' ', withheld)}");
        }

        var now = _time.GetUtcNow();

        // ───────── the grant this token hangs off ─────────
        //
        // Derived from (client, owner) rather than generated, so every token this service account
        // is ever issued carries the same grant id. Two things follow, and both are the reason:
        //
        //   - Revocation sticks. `RevokeAsync` on that id, or `RevokeAllForSubject` on the owner,
        //     stops the *next* token too, because the next request computes the same id and finds
        //     the row revoked. A fresh guid per request would mean revoking one token an instant
        //     before the client asks for another, forever.
        //   - The table does not grow. One row per service account, not one per hour per service
        //     account for as long as it runs.
        //
        // Sha-256 hex is 64 characters, which is exactly what the grant_id column holds. The two
        // inputs are separated by a newline so that a client id ending in the owner's prefix cannot
        // collide with a different pair.
        var grantId = DeriveGrantId(client.ClientId, owner);
        var existing = await _grants.FindAsync(grantId, cancellationToken);

        if (existing is { IsActive: false })
        {
            return Failed(
                ReasonCode.ClientCredentialsGrantRevoked,
                OAuthErrorCode.InvalidGrant,
                "This client's authorization has been revoked.",
                $"client_id={client.ClientId.Value}; grant_id={grantId}");
        }

        // Resources are resolved before the grant is written, so a request naming an unknown
        // resource does not leave a row behind for a token that was never issued.
        var permitted = existing?.Resources
            ?? Audience(await _resources.AllAsync(cancellationToken), client.AllowedScopes);

        var resolved = await ResourceNarrowing.ResolveAsync(
            parameters, permitted, client, _resources, cancellationToken);

        if (resolved.Error is { } resourceError)
        {
            return resourceError;
        }

        var grant = existing ?? new GrantRecord(
            GrantId: grantId,
            Subject: owner,
            ClientId: client.ClientId,
            Scope: client.AllowedScopes,
            Resources: permitted,
            CreatedAt: now,

            // AuthTime is the moment the credential was configured as far as anybody can tell from
            // here, and there is no better answer: no authentication event happened. It is recorded
            // as the first use rather than left null so that `auth_time` in the token is a real
            // instant, and so a stale service account is visible as one nobody has used lately.
            AuthTime: now);

        if (existing is null)
        {
            await _grants.StoreAsync(grant, cancellationToken);
        }

        // Scope from the record, not from `grant`, so that a client whose scopes were narrowed
        // after the grant row was written gets the narrower set on its next token. The grant is the
        // revocation handle; the client is the authority on what it may ask for.
        var tokens = await _issuer.IssueForClientCredentialsAsync(
            grant with { Scope = client.AllowedScopes },
            client,
            resolved.Resource!,
            client.AllowedScopes,
            now,
            cancellationToken);

        return new GrantOutcome.Issued(tokens);
    }

    /// <summary>
    /// Which resources a service account's own scopes can be for.
    /// </summary>
    /// <param name="registered">Everything the registry holds.</param>
    /// <param name="scopes">The scopes pinned on the client.</param>
    /// <returns>
    /// The one resource that defines every one of them, or all of them when that is not exactly one.
    /// </returns>
    /// <remarks>
    /// <para>
    /// <b>Why this grant may derive an audience where <c>/authorize</c> may not.</b> A-02 refuses to
    /// nominate a resource as soon as two are registered, because picking one would make the
    /// audience depend on registration order. That reasoning holds wherever the scope set arrives in
    /// the request — it can be anything, so it says nothing about which resource is meant. Here it
    /// cannot: <b>scope is fixed on the client</b>, so the complete set is known from the record
    /// before any request input is read. If exactly one registered resource defines all of it, that
    /// is a derivation rather than a guess, and every other resource would refuse a token carrying
    /// those scopes anyway.
    /// </para>
    /// <para>
    /// <b>What it fixes.</b> With two resources registered, a service account had to send
    /// <c>resource</c> or be refused <c>invalid_target</c> — so "copy the client id and the secret
    /// into your service" was not true, and the service failed at its first run naming a parameter
    /// nobody had mentioned. The credential is now self-contained in the case that has an
    /// unambiguous answer.
    /// </para>
    /// <para>
    /// <b>Scopes no resource defines are not evidence and are excluded.</b> <c>openid</c> and
    /// <c>offline_access</c> are the server's own and belong to no resource, so requiring a
    /// candidate to define them would match nothing and reinstate the refusal for a service account
    /// that happens to hold one. Note that a name like <c>email</c> may be OIDC's <i>and</i> a
    /// resource's, which is why this asks the registry what is defined rather than carrying a list
    /// of names it believes are OIDC's.
    /// </para>
    /// <para>
    /// <b>Ambiguous and empty both fall back to everything, which is the behaviour before this
    /// existed.</b> Two candidates is genuinely ambiguous and the caller must say. Zero means the
    /// registry declares no scopes for anything — a deployment this cannot reason about — and
    /// narrowing to nothing there would refuse a request that works today.
    /// </para>
    /// </remarks>
    internal static string[] Audience(IReadOnlyList<ResourceRegistration> registered, ScopeSet scopes)
    {
        var all = registered.Select(r => r.Resource.Canonical).ToArray();

        // Ordinal throughout, matching every other scope comparison in this server.
        var defined = scopes.Values
            .Where(s => registered.Any(r => r.Scopes.Contains(s)))
            .ToArray();

        if (defined.Length == 0)
        {
            return all;
        }

        var candidates = registered
            .Where(r => defined.All(s => r.Scopes.Contains(s)))
            .Select(r => r.Resource.Canonical)
            .ToArray();

        return candidates.Length == 1 ? candidates : all;
    }

    /// <summary>The stable grant id for a (client, owner) pair.</summary>
    /// <remarks>
    /// Public because revoking a service account requires computing it. The grant id is not handed
    /// out anywhere else — there is no authorization request to read it from and no consent row to
    /// look it up in — so an administrator who wants to stop one has to be able to derive it from
    /// the two things they do know. Keeping it internal would mean the only way to revoke a service
    /// account is to find its row by scanning.
    /// </remarks>
    /// <param name="clientId">The client.</param>
    /// <param name="owner">The account it acts as.</param>
    /// <returns>The grant id, lowercase hex, 64 characters.</returns>
    public static string DeriveGrantId(ClientIdentifier clientId, SubjectId owner)
    {
        var material = Encoding.UTF8.GetBytes(
            string.Create(CultureInfo.InvariantCulture, $"{clientId.Value}\n{owner.Value}"));

        return Convert.ToHexStringLower(SHA256.HashData(material));
    }

    private static GrantOutcome.Failed Failed(
        ReasonCode reason, OAuthErrorCode error, string description, string detail) =>
        new(Rejection.Of(reason, error, description, detail));
}
