using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.OAuth.Tokens;

/// <summary>
/// Everything needed to mint one access token. RFC 9068 §2.2.
/// </summary>
/// <param name="Issuer">The <c>iss</c>. One configured string, never derived from the request.</param>
/// <param name="Audience">
/// The <c>aud</c>. <b>Non-nullable, and obtainable only from the resource registry</b> — which is
/// how N-01 stops being a rule and becomes a fact about the type system. There is no way to
/// construct this record without a resource that was validated, so "accept <c>resource</c> and
/// ignore it" and "fall back to a default audience" have no code path.
/// </param>
/// <param name="Subject">The <c>sub</c>.</param>
/// <param name="ClientId">The <c>client_id</c> claim, required by RFC 9068 §2.2.</param>
/// <param name="GrantId">
/// Our own grant identifier, emitted as <c>jti</c>'s companion so a resource server can consult a
/// revocation denylist without introspection.
/// </param>
/// <param name="Scope">The <c>scope</c> claim, emitted as a space-delimited string per §2.2.3.</param>
/// <param name="IssuedAt">The <c>iat</c>.</param>
/// <param name="ExpiresAt">The <c>exp</c>.</param>
/// <param name="JwtId">The <c>jti</c>.</param>
/// <param name="AuthTime">When the user actually authenticated, for <c>auth_time</c>.</param>
/// <param name="Extra">
/// Additional claims. The seam for a future <c>cnf</c>/<c>jkt</c> if DPoP is ever added, so that
/// deferral does not require restructuring the mint path.
/// </param>
public sealed record AccessTokenDescriptor(
    IssuerString Issuer,
    ResourceIdentifier Audience,
    SubjectId Subject,
    ClientIdentifier ClientId,
    string GrantId,
    ScopeSet Scope,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string JwtId,
    DateTimeOffset? AuthTime = null,
    IReadOnlyDictionary<string, object?>? Extra = null);

/// <summary>
/// Everything needed to mint one ID token. OIDC Core §2.
/// </summary>
/// <param name="Issuer">The <c>iss</c>.</param>
/// <param name="Audience">
/// The <c>aud</c>, which is the <b>client</b>.
/// </param>
/// <param name="Subject">The <c>sub</c>.</param>
/// <param name="IssuedAt">The <c>iat</c>.</param>
/// <param name="ExpiresAt">The <c>exp</c>.</param>
/// <param name="AuthTime">The <c>auth_time</c>, when the request asked for it or <c>max_age</c> was used.</param>
/// <param name="Nonce">
/// The <c>nonce</c> from the authorization request, echoed verbatim. <b>Never invented</b>: OIDC
/// Core requires the value the client sent and nothing else, and a server-generated nonce would
/// silently pass a replay check the client believes it is performing.
/// </param>
/// <param name="AccessTokenHash">The <c>at_hash</c>, when an access token is issued alongside.</param>
/// <param name="Extra">Additional claims from the claims mapper.</param>
/// <remarks>
/// N-10 lives in the type signature. <see cref="Audience"/> here is a
/// <see cref="ClientIdentifier"/> while <see cref="AccessTokenDescriptor.Audience"/> is a
/// <see cref="ResourceIdentifier"/>, so passing one where the other belongs does not compile. The
/// two audiences serve opposite purposes — an ID token says "this is who signed in, and it is for
/// you, the client", an access token says "present this to that resource" — and unifying them
/// breaks every conformant relying party at OIDC Core §3.1.3.7 rule 3.
/// </remarks>
public sealed record IdTokenDescriptor(
    IssuerString Issuer,
    ClientIdentifier Audience,
    SubjectId Subject,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? AuthTime = null,
    string? Nonce = null,
    string? AccessTokenHash = null,
    IReadOnlyDictionary<string, object?>? Extra = null);

/// <summary>A minted token, ready to put in a response.</summary>
/// <param name="Wire">
/// The compact serialization — <b>a live credential</b>, and the most valuable one this assembly
/// produces.
/// </param>
/// <param name="ExpiresAt">When it expires, for the response's <c>expires_in</c>.</param>
/// <param name="Kid">Which key signed it, for diagnostics.</param>
/// <remarks>
/// <para>
/// The <see cref="System.Text.Json.Serialization.JsonIgnoreAttribute"/> and the
/// <see cref="ToString"/> override are the same defence <c>OpaqueSecret</c> carries, and this type
/// needed it more: a positional record's compiler-generated <c>ToString</c> prints
/// <i>every</i> property, so <c>$"{token}"</c> or a <c>LogInformation("{Token}", token)</c> emitted
/// the whole access token — a signed, valid, unexpired one — into whatever the logs are shipped to.
/// Nothing in this repository did that. Nothing stopped it either.
/// </para>
/// <para>
/// It is still reachable by a logger that destructures over properties. See
/// <c>SecretsDoNotSerializeTests</c>, which pins that as a known open route and is why Serilog is
/// not a dependency here.
/// </para>
/// </remarks>
public sealed record MintedToken(
    [property: System.Text.Json.Serialization.JsonIgnore]
    [property: System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
    string Wire,
    DateTimeOffset ExpiresAt,
    string Kid)
{
    /// <summary>Never returns the token. Replaces the record's generated member-wise rendering.</summary>
    public override string ToString() => $"MintedToken {{ Kid = {Kid}, ExpiresAt = {ExpiresAt:O}, Wire = <redacted> }}";
}
