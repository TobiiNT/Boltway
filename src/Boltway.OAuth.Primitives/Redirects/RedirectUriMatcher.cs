namespace Boltway.OAuth.Primitives.Redirects;

/// <summary>
/// Matches a requested redirect URI against a client's registrations.
/// </summary>
/// <remarks>
/// <para>
/// The single most security-sensitive function in the server. Everything it compares is a
/// <see cref="string"/> or a <see cref="bool"/>; there is not one reference to <see cref="Uri"/> in
/// this file, and an architecture test asserts that transitively over the compiled IL — including
/// through every method this one calls. Transitivity is the point: without it the violation just
/// moves one helper away.
/// </para>
/// <para>
/// There is no <c>IRedirectUriMatcher</c> seam, deliberately. This is one of the places where
/// flexibility <i>is</i> the vulnerability: a customer-supplied matcher that accepts a prefix or a
/// wildcard is an open redirector on a domain the user has been taught to trust, and it leaks
/// <c>code</c> and <c>state</c> to whoever asked. There is nothing here worth configuring.
/// </para>
/// </remarks>
public static class RedirectUriMatcher
{
    /// <summary>
    /// Find the registration matching <paramref name="requested"/>, or
    /// <see cref="RedirectMatch.None"/>.
    /// </summary>
    /// <param name="requested">The redirect URI from the authorization request.</param>
    /// <param name="registrations">The client's registered redirect URIs.</param>
    public static RedirectMatch Match(
        in RequestedRedirectUri requested,
        IReadOnlyList<RegisteredRedirectUri> registrations)
    {
        ArgumentNullException.ThrowIfNull(registrations);

        // Both value types are public structs, so `default(T)` is constructible by anyone and its
        // Value is null despite the non-nullable declaration. string.Equals(null, null, Ordinal) is
        // true, so without this guard `Match(default, [default])` returns a successful Exact match
        // — and a successful match is the capability token that authorizes a redirect at all.
        // Refuse the whole call rather than skipping the row: a default here means a caller built
        // a redirect URI without going through a factory, which is a bug wherever it happened.
        if (requested.Value is null)
        {
            return RedirectMatch.None;
        }

        // Step 1 — RFC 3986 §6.2.1 Simple String Comparison, character by character on the raw
        // strings. This is the whole rule for https and private-use-scheme clients, and it runs
        // first so that a loopback registration still gets an exact match when the ports agree.
        for (var i = 0; i < registrations.Count; i++)
        {
            if (registrations[i].Value is null)
            {
                continue;
            }

            if (string.Equals(requested.Value, registrations[i].Value, StringComparison.Ordinal))
            {
                return RedirectMatch.Exact(registrations[i], requested.Value);
            }
        }

        // Step 2 — RFC 8252 §7.3, and nothing else reaches it.
        //
        // Kept as a visibly separate branch rather than folded into the loop above, because the
        // failure mode here is not "the code is wrong" but "the exception applies to something it
        // should not". A reader has to be able to see the gate.
        //
        // The gate is: the REGISTRATION says Loopback. Not the request. A request cannot promote
        // itself into port-agnostic matching by pointing at localhost, which is what makes
        // https://claude.ai:1337/api/mcp/auth_callback stay refused.
        for (var i = 0; i < registrations.Count; i++)
        {
            var registration = registrations[i];

            if (registration.Kind != RedirectKind.Loopback || requested.Kind != RedirectKind.Loopback)
            {
                continue;
            }

            // Everything except the port, and all of it exact on values cut from the raw strings.
            //
            // Dropping the path would let any process on the user's machine that can bind a port
            // harvest authorization codes. Taking the path from Uri would be nearly as bad in a
            // quieter way: GetComponents(Path, UriEscaped) resolves dot segments and percent-decodes
            // unreserved characters, so /a/../callback, /a/%2e%2e/callback and /%63allback all
            // arrive as "callback" and match a registration containing none of them.
            if (string.Equals(requested.Host, registration.Host, StringComparison.Ordinal)
                && string.Equals(requested.PathAndQuery, registration.PathAndQuery, StringComparison.Ordinal))
            {
                return RedirectMatch.LoopbackPortIgnored(registration, requested.Value);
            }
        }

        return RedirectMatch.None;
    }
}
