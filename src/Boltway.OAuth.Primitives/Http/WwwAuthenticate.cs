using System.Text;

namespace Boltway.OAuth.Primitives.Http;

/// <summary>
/// Builds the <c>WWW-Authenticate: Bearer …</c> challenge, RFC 6750 §3 and RFC 9728 §5.1.
/// </summary>
/// <remarks>
/// <para>
/// This header is the hinge the whole authorization flow turns on. A client that cannot read it
/// cannot discover the authorization server, so it never starts the flow, and the user sees
/// "couldn't connect" with nothing to act on.
/// </para>
/// <para>
/// The failure mode worth naming: <c>error_description</c> is the one parameter carrying
/// human-written text, and a stray <c>"</c> in it terminates the quoted string early. Everything
/// after that point - including <c>resource_metadata</c>, which is the entire discovery pointer -
/// is parsed as garbage or dropped. So a careless error message does not degrade the diagnostics;
/// it removes the client's only route to authenticating at all.
/// </para>
/// <para>
/// The defence here is to <b>strip</b> characters outside the permitted set rather than escape
/// them. RFC 6750 §3 defines <c>error</c> and <c>error_description</c> over
/// <c>%x20-21 / %x23-5B / %x5D-7E</c> - a range that excludes <c>"</c> and <c>\</c> outright - so a
/// backslash-escaped quote is not a legal value even though RFC 7235's <c>quoted-string</c> grammar
/// would carry it. Emitting one means betting on the client's parser. Stripping means the header is
/// always well-formed and always parseable, at the cost of some punctuation in a message no
/// protocol depends on.
/// </para>
/// </remarks>
public static class WwwAuthenticate
{
    /// <summary>Longest <c>error_description</c> emitted.</summary>
    public const int MaxDescriptionLength = 240;

    /// <summary>
    /// Longest challenge emitted, in bytes. Beyond this the whole header is at risk.
    /// </summary>
    /// <remarks>
    /// Capping only <c>error_description</c> left <c>realm</c>, <c>resource_metadata</c> and the
    /// scope list unbounded, so a long realm or a client entitled to many scopes could push the
    /// header past a reverse proxy's buffer - nginx's <c>proxy_buffer_size</c> defaults to 4 KB -
    /// and turn it into a 502. The client then sees no <c>resource_metadata</c> at all, which is
    /// precisely the failure this whole type exists to prevent, arriving by a different route.
    /// </remarks>
    public const int MaxHeaderLength = 3072;

    /// <summary>
    /// Build a Bearer challenge.
    /// </summary>
    /// <param name="error">
    /// RFC 6750 error code, or <see langword="null"/>. RFC 6750 §3.1 says to omit it when the
    /// request carried no credentials at all - but both Claude and ChatGPT need it present to
    /// trigger their re-authentication UI, and a challenge they ignore is worse than a slightly
    /// over-specified one, so callers pass <c>invalid_token</c> even in that case.
    /// </param>
    /// <param name="errorDescription">Human-readable detail. Sanitized, then capped.</param>
    /// <param name="resourceMetadataUrl">
    /// RFC 9728 §5.1 pointer to the protected-resource metadata. This is what the client follows to
    /// find the authorization server.
    /// </param>
    /// <param name="scopes">Scopes that would satisfy the request. Required on <c>insufficient_scope</c>.</param>
    /// <param name="realm">RFC 7235 realm. Rarely useful; supported because the grammar has it.</param>
    public static string Bearer(
        string? error = null,
        string? errorDescription = null,
        string? resourceMetadataUrl = null,
        IReadOnlyList<string>? scopes = null,
        string? realm = null)
    {
        var builder = new StringBuilder("Bearer");
        var first = true;

        Append(builder, "realm", realm, ref first);
        Append(builder, "error", error, ref first);
        Append(builder, "error_description", Truncate(errorDescription), ref first);
        Append(builder, "resource_metadata", resourceMetadataUrl, ref first);

        if (scopes is { Count: > 0 })
        {
            Append(builder, "scope", JoinScopes(scopes), ref first);
        }

        var header = builder.ToString();

        // Truncating a challenge would produce a malformed one, so an over-long header drops the
        // optional parameters and keeps the two the client cannot act without.
        return header.Length <= MaxHeaderLength
            ? header
            : Bearer(error, errorDescription: null, resourceMetadataUrl, scopes: null, realm: null);
    }

    /// <summary>
    /// Build a challenge for a failed <b>client</b> authentication at the token endpoint.
    /// </summary>
    /// <param name="scheme">
    /// The scheme the client used, echoed back. RFC 6749 §5.2 requires the challenge to match "the
    /// authentication scheme used by the client", and that is not decoration: a client that sent
    /// Basic credentials and receives a Bearer challenge is being told to fix the wrong thing.
    /// </param>
    /// <param name="realm">RFC 7235 realm.</param>
    /// <remarks>
    /// Separate from <see cref="Bearer"/> because the two challenges answer different questions.
    /// Bearer is what a <i>resource</i> server sends about an access token; this is what the
    /// <i>authorization</i> server sends about a client credential, and RFC 6750's <c>error</c> and
    /// <c>scope</c> parameters have no meaning in that context.
    /// </remarks>
    public static string ClientAuthentication(string scheme, string? realm = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(scheme);

        // The scheme is chosen from a closed set by the caller, never taken from the request. An
        // attacker-supplied scheme would be an injection point into the header, and the Sanitize
        // below would only make that quiet rather than safe.
        if (!MediaType.IsToken(scheme))
        {
            throw new ArgumentOutOfRangeException(nameof(scheme), scheme, "An auth scheme must be an RFC 7230 token.");
        }

        var builder = new StringBuilder(scheme);
        var first = true;

        Append(builder, "realm", realm, ref first);

        return builder.ToString();
    }

    private static void Append(StringBuilder builder, string name, string? value, ref bool first)
    {
        if (string.IsNullOrEmpty(value))
        {
            return;
        }

        var sanitized = Sanitize(value);
        if (sanitized.Length == 0)
        {
            return;
        }

        // Comma between parameters, single space after the scheme. RFC 7235 §4.1.
        builder.Append(first ? ' ' : ", ");
        first = false;

        // Always a quoted-string, never a bare token. A URL contains ':' and '/', which are not
        // tchar, so resource_metadata unquoted is not merely ugly - it is unparseable.
        builder.Append(name).Append("=\"").Append(sanitized).Append('"');
    }

    /// <summary>
    /// Join scopes, dropping any that is not an RFC 6749 §3.3 <c>scope-token</c>.
    /// </summary>
    /// <remarks>
    /// Validated before the join, not sanitised after it. Sanitising afterwards turns a space
    /// inside one scope into a separator, so <c>["story:read story:write"]</c> becomes two scopes
    /// and <c>["a\"b", "c"]</c> becomes three - and an empty element yields a double space, which
    /// is not a legal <c>scope</c> value at all. This header is the only thing that tells a client
    /// what to re-authorise for (X-34), so a mangled list means it asks for the wrong scope and
    /// keeps being refused.
    /// </remarks>
    private static string JoinScopes(IReadOnlyList<string> scopes)
    {
        var valid = new List<string>(scopes.Count);

        foreach (var scope in scopes)
        {
            if (!string.IsNullOrEmpty(scope) && IsScopeToken(scope))
            {
                valid.Add(scope);
            }
        }

        return string.Join(' ', valid);
    }

    /// <summary>RFC 6749 §3.3 <c>scope-token</c>: <c>%x21 / %x23-5B / %x5D-7E</c>. No space.</summary>
    private static bool IsScopeToken(string scope)
    {
        foreach (var c in scope)
        {
            if (c is not ('\x21' or (>= '\x23' and <= '\x5B') or (>= '\x5D' and <= '\x7E')))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Reduce a value to the RFC 6750 §3 character set: <c>%x20-21 / %x23-5B / %x5D-7E</c>.
    /// </summary>
    /// <remarks>
    /// Excludes <c>"</c> (%x22) and <c>\</c> (%x5C) by construction, and everything below %x20 -
    /// so a newline or a carriage return in a message cannot split the header and inject another
    /// one. Response splitting through an error message is a real class of bug and this is where it
    /// is closed.
    /// </remarks>
    private static string Sanitize(string value)
    {
        var builder = new StringBuilder(value.Length);

        foreach (var c in value)
        {
            if (c is (>= '\x20' and <= '\x21') or (>= '\x23' and <= '\x5B') or (>= '\x5D' and <= '\x7E'))
            {
                builder.Append(c);
            }
            else if (c is '"' or '\\' or '\n' or '\r' or '\t')
            {
                // Collapse the dangerous ones to a space rather than deleting them, so
                // `say "no"` reads as `say  no ` instead of `say no` - the shape of the original
                // survives, which matters when someone is comparing a log line to a header.
                builder.Append(' ');
            }
        }

        return builder.ToString().Trim();
    }

    private static string? Truncate(string? value) =>
        value is { Length: > MaxDescriptionLength } ? value[..MaxDescriptionLength] : value;
}
