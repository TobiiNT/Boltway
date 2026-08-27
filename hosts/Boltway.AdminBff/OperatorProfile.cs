using System.Net.Http.Headers;
using System.Text.Json;

namespace Boltway.AdminBff;

/// <summary>
/// What the operator is called, asked of the authorization server's <c>/userinfo</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>The rail named people by ULID, and that is what this is for.</b> The shell has always drawn
/// whoever is signed in above the sign-out control; what it drew was
/// <c>01KZX253NGXW6MPB13Y4X2GPE7</c>. Not a defect in the shell - this server's ID token carries
/// <c>sub iss aud exp iat auth_time nonce at_hash</c> and nothing else, so both name lookups in
/// <c>Who</c> miss and it falls through to the subject. An operator checking which account they are
/// signed in as had 26 characters to compare against a table whose first column is the handle.
/// </para>
/// <para>
/// <b><c>/userinfo</c> is the channel, and it is the only one.</b> A client that is not the resource
/// server has no business parsing the access token - it is not the audience - and
/// <c>UserInfoEndpoint</c>'s own remarks put it plainly: a client that needs to know who signed in
/// has exactly two channels, the ID token and there. The ID token does not carry a name, so this is
/// the other one.
/// </para>
/// <para>
/// <b>No new scope, and adding the obvious one would break sign-in.</b> That endpoint releases
/// <c>preferred_username</c> to any token granted <c>openid</c> - deliberately, with the argument
/// written out beside it, because the access token already carries the same fact ungated. Adding
/// <c>profile</c> here to look more like OIDC would be refused with <c>invalid_scope</c> before a
/// page ever rendered: <c>profile</c> is not a scope this server knows, since
/// <c>scopes_supported</c> is whatever a deployment configured.
/// </para>
/// <para>
/// <b>A refusal is <see langword="null"/>, and that is why this is not
/// <c>GetClaimsFromUserInfoEndpoint</c>.</b> The framework's switch fetches the same document and
/// fails the sign-in when it cannot, which would let a label the shell draws in eleven-pixel grey
/// stop an operator entering the admin UI at all. <c>UserInfoEnabled</c> defaults to true and is a
/// deployment's to turn off; on one that has, that switch is a sign-in that dies at the profile
/// fetch with a 401 nobody would connect to the setting. This is the trade the account page's
/// service-account section already makes: ask separately, and render what came back.
/// </para>
/// </remarks>
public static class OperatorProfile
{
    /// <summary>
    /// The claim this produces, which is the first thing the shell's lookup asks for.
    /// </summary>
    /// <remarks>
    /// Spelled as the wire spells it, and it stays that way because nothing renames it on this path:
    /// the value is read out of a JSON document and added under this exact type. The ID token's
    /// <c>sub</c> is the counter-example and cost this app a dead lookup for a release - the
    /// handler's <c>MapInboundClaims</c> turns it into <c>ClaimTypes.NameIdentifier</c> before the
    /// principal exists, so <c>FindFirst("sub")</c> matched nothing while looking right.
    /// </remarks>
    public const string ClaimType = "preferred_username";

    /// <summary>
    /// Ask what this token's holder is called.
    /// </summary>
    /// <param name="client">
    /// The backchannel to send on. The handler's own, so this inherits its timeout, its proxy and
    /// its certificate handling rather than establishing a second opinion about any of them.
    /// </param>
    /// <param name="userInfoEndpoint">
    /// Where to ask, out of the discovery document. <see langword="null"/> or empty when the server
    /// advertises none, which is a deployment that turned the endpoint off - an answer, not a
    /// failure, and the reason this is read from the document rather than composed from the
    /// authority.
    /// </param>
    /// <param name="accessToken">The token minted for this sign-in.</param>
    /// <param name="ct">The request's own cancellation.</param>
    /// <returns>
    /// The handle, or <see langword="null"/> when the server did not supply one.
    /// </returns>
    /// <remarks>
    /// <para>
    /// <b>Every answer that is not a handle is <see langword="null"/>, and none of them is an
    /// exception.</b> A 404 is a server that does not serve this endpoint, a 401 or 403 is a token
    /// this endpoint will not take, and a body without the claim is an account with no username. All
    /// four are ordinary and all four end with the rail naming somebody by subject.
    /// </para>
    /// <para>
    /// <b>A transport failure is not caught here, on purpose.</b> It is the one outcome worth a line
    /// in a log, and the log belongs at the call site, which knows this ran during a sign-in and can
    /// say what the operator will see instead. Swallowing it here would make that impossible to
    /// write.
    /// </para>
    /// </remarks>
    public static async Task<string?> HandleAsync(
        HttpClient client, string? userInfoEndpoint, string? accessToken, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);

        // Neither is worth a request. An absent endpoint is a server that does not serve one; an
        // absent token would be asking a bearer-only endpoint to answer anonymously, which it
        // refuses - and both would be a round trip to learn what is already known here.
        if (userInfoEndpoint is not { Length: > 0 } || accessToken is not { Length: > 0 })
        {
            return null;
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await client.SendAsync(request, ct);

        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        // Parsed from the string rather than through ReadFromJsonAsync, and the difference is a
        // failure mode rather than a preference: that helper checks the media type first and throws
        // NotSupportedException - not JsonException - for a 200 that came back as text/html. A
        // proxy's error page is exactly the case this has to survive, so the check that would
        // refuse it before parsing is the one to do without.
        try
        {
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));

            // GetString allocates its own string, so the value outlives the document it came from.
            return body.RootElement.ValueKind is JsonValueKind.Object
                && body.RootElement.TryGetProperty(ClaimType, out var handle)
                && handle.ValueKind is JsonValueKind.String
                && handle.GetString() is { Length: > 0 } value
                    ? value
                    : null;
        }
        catch (JsonException)
        {
            // A 200 carrying something that is not JSON is a proxy's page or a bug on the other
            // side. The status was the only part that suggested an answer; there is none.
            return null;
        }
    }
}
