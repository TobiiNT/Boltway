namespace Boltway.AuthorizationServer.Interaction;

/// <summary>
/// Whether a <c>returnUrl</c> is a local path this server may redirect to.
/// </summary>
/// <remarks>
/// <para>
/// N-11 and the design both name <c>Url.IsLocalUrl</c>. That method cannot be called from here:
/// its implementation is <c>Microsoft.AspNetCore.Internal.SharedUrlHelper</c>, which is
/// <see langword="internal"/> in every assembly that carries it, and the only public entry point is
/// MVC's <c>IUrlHelper</c> instance method - which needs <c>AddMvcCore</c>, an
/// <c>IUrlHelperFactory</c> and an <c>ActionContext</c>. This project is minimal-API with a bare
/// framework reference, and taking an MVC dependency for one predicate is a worse trade than
/// writing the predicate. <c>Results.LocalRedirect</c> is not an escape hatch either: it emits 302,
/// and E-20 mandates 303.
/// </para>
/// <para>
/// This is <b>stricter</b> than the framework's version in one way that matters. That one accepts
/// <c>~/…</c>, which is MVC content-root syntax and not a valid <c>Location</c> - emitted raw, a
/// browser resolves it relative to the current path and the user lands on <c>/~/consent</c>. Here a
/// value must begin with a single <c>/</c>.
/// </para>
/// <para>
/// What it defends: <c>/login</c> and <c>/consent</c> are pages on the one origin the user has been
/// taught to type a password into. A <c>returnUrl</c> of <c>//evil.example</c> turns that login page
/// into a redirector to a pixel-perfect copy, where none of this server's headers apply - and the
/// user got there from a URL on a domain they trust. RFC 9700 §2.1: servers "MUST NOT expose URLs
/// that forward the user's browser to arbitrary URIs obtained from a query parameter".
/// </para>
/// </remarks>
public static class LocalUrl
{
    /// <summary>
    /// Whether this is a local path.
    /// </summary>
    /// <param name="url">
    /// The <b>decoded</b> value, as <c>Request.Query</c> hands it over. Checking before decoding
    /// lets <c>%2F%2Fevil.example</c> through, because the check then sees one literal percent sign
    /// where the browser will later see two slashes.
    /// </param>
    public static bool IsLocal(string? url)
    {
        // Empty is not a redirect target. An "empty means home" convenience here would mean a
        // stripped parameter silently sends the user somewhere other than where they were going.
        if (string.IsNullOrEmpty(url) || url[0] != '/')
        {
            return false;
        }

        if (url.Length == 1)
        {
            return true;
        }

        // "//evil.example" is a scheme-relative URL: the browser reads it as an absolute address on
        // another host. "/\evil.example" is the same thing to every browser that normalises a
        // backslash to a slash, which is all of them.
        if (url[1] is '/' or '\\')
        {
            return false;
        }

        // Control characters, TAB, CR and LF included. The WHATWG URL parser strips them before
        // resolving, so "/\t/evil.example" is a scheme-relative URL that does not look like one to
        // a naive check - and CR or LF in a value destined for a Location header is response
        // splitting.
        foreach (var c in url.AsSpan(1))
        {
            if (char.IsControl(c))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Whether this is a local path <b>to the expected page</b>.
    /// </summary>
    /// <param name="url">The decoded <c>returnUrl</c>.</param>
    /// <param name="expectedPath">The one path a caller is allowed to be sent back to.</param>
    /// <remarks>
    /// "Local" is not the same question as "the page you meant". <c>/logout?post_logout_redirect_uri=…</c>
    /// is perfectly local and is not somewhere a consent page should hand a user. The interaction
    /// endpoints resume exactly one thing - the authorization request - so they check for exactly
    /// that path rather than for local-ness alone.
    /// </remarks>
    public static bool IsLocalPathTo(string? url, string expectedPath)
    {
        if (!IsLocal(url))
        {
            return false;
        }

        return string.Equals(PathOf(url!), expectedPath, StringComparison.Ordinal);
    }

    /// <summary>
    /// Whether this is a local path to <b>one of</b> a closed set of pages.
    /// </summary>
    /// <param name="url">The decoded <c>returnUrl</c>.</param>
    /// <param name="expectedPaths">Every path a caller is allowed to be sent back to.</param>
    /// <remarks>
    /// <para>
    /// The sign-in page used to resume exactly one thing, so <see cref="IsLocalPathTo"/> took one
    /// path. It now resumes two kinds of thing - an authorization request, or a self-service page a
    /// person was sent to <c>/login</c> from - and this is the widening that allows the second
    /// without allowing anything else.
    /// </para>
    /// <para>
    /// <b>A closed set, not "any local path".</b> That distinction is the whole value of the check.
    /// Local-ness alone would let <c>/logout?post_logout_redirect_uri=…</c> or any future page
    /// through, and the list of pages it is sensible to land on after signing in is short, known at
    /// compile time, and not something a query string should get to extend.
    /// </para>
    /// </remarks>
    public static bool IsLocalPathToAny(string? url, IReadOnlyList<string> expectedPaths)
    {
        ArgumentNullException.ThrowIfNull(expectedPaths);

        if (!IsLocal(url))
        {
            return false;
        }

        var path = PathOf(url!);

        for (var i = 0; i < expectedPaths.Count; i++)
        {
            if (string.Equals(path, expectedPaths[i], StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static string PathOf(string url)
    {
        var queryStart = url.IndexOf('?', StringComparison.Ordinal);

        return queryStart < 0 ? url : url[..queryStart];
    }
}
