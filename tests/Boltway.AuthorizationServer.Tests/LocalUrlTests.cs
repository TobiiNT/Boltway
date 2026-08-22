using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Interaction;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The <c>returnUrl</c> gate, pinned before anything depends on it.
/// </summary>
/// <remarks>
/// N-11 names <c>Url.IsLocalUrl</c>, which cannot be called from a minimal-API project — its
/// implementation is <c>internal</c> and the only public entry is MVC's <c>IUrlHelper</c>. So this
/// is a re-implementation, and a re-implemented security predicate with no test matrix is worse
/// than the dependency it avoided.
/// </remarks>
public sealed class LocalUrlTests
{
    /// <summary>Values that must be refused.</summary>
    /// <remarks>
    /// Each row is a way to write "somewhere else" that looks local. <c>//host</c> is a
    /// scheme-relative URL; <c>/\host</c> is the same thing to every browser, all of which normalise
    /// a backslash to a slash; the control-character rows exploit the WHATWG URL parser stripping
    /// TAB, CR and LF <i>before</i> resolving, so the browser sees <c>//evil.example</c> where a
    /// naive check saw a path. <c>~/</c> is the one the framework's own version accepts — it is MVC
    /// content-root syntax, not a URL, and a browser resolves it relative to the current path.
    /// </remarks>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("//evil.example")]
    [InlineData("//evil.example/authorize")]
    [InlineData("/\\evil.example")]
    [InlineData("/\\/evil.example")]
    [InlineData("https://evil.example")]
    [InlineData("http://evil.example")]
    [InlineData("\\\\evil.example")]
    [InlineData("evil.example")]
    [InlineData("~/authorize")]
    [InlineData("~//evil.example")]
    [InlineData("/\t//evil.example")]
    [InlineData("/\n//evil.example")]
    [InlineData("/authorize\r\nSet-Cookie: x=1")]
    [InlineData("javascript:alert(1)")]
    public void A_non_local_url_is_refused(string? url) => Assert.False(LocalUrl.IsLocal(url));

    /// <summary>Values that must be accepted, so the refusals above are not vacuous.</summary>
    [Theory]
    [InlineData("/")]
    [InlineData("/authorize")]
    [InlineData("/authorize?client_id=x&scope=a%20b")]
    [InlineData("/a/b/c")]
    public void A_local_path_is_accepted(string url) => Assert.True(LocalUrl.IsLocal(url));

    /// <summary>
    /// Local is not the same question as "the page you meant".
    /// </summary>
    /// <remarks>
    /// <c>/logout?post_logout_redirect_uri=…</c> is perfectly local and is not somewhere a consent
    /// page should hand a user. The interaction endpoints resume exactly one thing.
    /// </remarks>
    [Theory]
    [InlineData("/authorize", true)]
    [InlineData("/authorize?client_id=x", true)]
    [InlineData("/logout", false)]
    [InlineData("/logout?post_logout_redirect_uri=https://evil.example", false)]
    [InlineData("/authorize/../logout", false)]
    [InlineData("//evil.example/authorize", false)]
    public void Only_the_expected_path_resumes(string url, bool expected) =>
        Assert.Equal(expected, LocalUrl.IsLocalPathTo(url, AuthorizationServerPaths.Authorize));
}
