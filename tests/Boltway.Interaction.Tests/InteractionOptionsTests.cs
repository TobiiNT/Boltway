using Boltway.AuthorizationServer.Configuration;

using Boltway.Interaction.Testing;

namespace Boltway.Interaction.Tests;

/// <summary>
/// What a deployment may point the pages at.
/// </summary>
/// <remarks>
/// Every rejection here is a page that would have rendered wrong in production and right in a
/// fixture, because the thing that refuses it is the browser applying a policy no test client
/// enforces. Startup is the only place the operator who configured it is still watching.
/// </remarks>
public sealed class InteractionOptionsTests
{
    [Theory]
    [InlineData("/")]
    [InlineData("/css/authorization.css")]
    [InlineData("/css/authorization.css?v=2")]
    [InlineData("/static/a/b/c.css")]
    public void A_path_on_this_origin_is_accepted(string path)
    {
        var options = new InteractionOptions();
        options.StylesheetPaths.Add(path);

        Assert.True(options.TryValidate(out var errors), string.Join("; ", errors));
    }

    /// <summary>
    /// Everything a browser would fetch from somewhere else, or refuse outright.
    /// </summary>
    /// <remarks>
    /// The two spellings of protocol-relative are the rows that matter. <c>//evil.example/x.css</c>
    /// looks like a path and is not one, and <c>/\evil.example/x.css</c> is the same thing written to
    /// survive a check that only looked for two slashes — browsers normalise the backslash. Neither
    /// would be blocked by <c>default-src 'self'</c> in a way anyone would notice: the page just
    /// renders unstyled, and the operator concludes the CSS is broken.
    /// </remarks>
    [Theory]
    [InlineData("")]
    [InlineData("css/authorization.css")]
    [InlineData("//evil.example/theme.css")]
    [InlineData("/\\evil.example/theme.css")]
    [InlineData("https://cdn.example.com/theme.css")]
    [InlineData("http://cdn.example.com/theme.css")]
    [InlineData("data:text/css,body{color:red}")]
    [InlineData("javascript:alert(1)")]
    [InlineData("/css/two words.css")]
    [InlineData("/css/\"onload=alert(1).css")]
    [InlineData("/café.css")]
    public void Anything_the_browser_would_fetch_elsewhere_is_refused(string path)
    {
        var options = new InteractionOptions();
        options.StylesheetPaths.Add(path);

        Assert.False(options.TryValidate(out var errors));
        Assert.Contains(errors, error => error.Contains("StylesheetPaths[0]", StringComparison.Ordinal));
    }

    [Fact]
    public void A_logo_off_this_origin_is_refused()
    {
        var options = new InteractionOptions { LogoPath = "https://cdn.example.com/logo.svg" };

        Assert.False(options.TryValidate(out var errors));
        Assert.Contains(errors, error => error.Contains("LogoPath", StringComparison.Ordinal));
    }

    [Fact]
    public void No_logo_is_not_a_bad_logo()
    {
        Assert.True(new InteractionOptions().TryValidate(out _));
    }

    [Fact]
    public void A_product_name_past_the_cap_is_refused()
    {
        var options = new InteractionOptions
        {
            ProductName = new string('x', InteractionOptions.MaxProductNameLength + 1),
        };

        Assert.False(options.TryValidate(out var errors));
        Assert.Contains(errors, error => error.Contains("ProductName", StringComparison.Ordinal));
    }

    /// <summary>
    /// Every problem, not the first.
    /// </summary>
    /// <remarks>
    /// A-12. An operator fixing a misconfiguration one restart at a time is the experience the
    /// collecting validator exists to prevent, and a nested options object that returns early
    /// reintroduces it one section at a time.
    /// </remarks>
    [Fact]
    public void Validation_reports_every_problem_at_once()
    {
        var options = new InteractionOptions
        {
            LogoPath = "//evil.example/logo.svg",
            ProductName = new string('x', InteractionOptions.MaxProductNameLength + 1),
        };

        options.StylesheetPaths.Add("https://cdn.example.com/a.css");
        options.StylesheetPaths.Add("also-not-a-path.css");

        Assert.False(options.TryValidate(out var errors));
        Assert.Equal(4, errors.Count);
    }

    /// <summary>The nested options are frozen with the rest, not left mutable behind them.</summary>
    /// <remarks>
    /// The renderer is a singleton holding this instance, so a host that added a stylesheet after
    /// startup would change every page from that moment — a configuration change with no restart,
    /// no validation and no record. <c>Freeze</c> is internal, so this reaches it the way the
    /// registration extension does.
    /// </remarks>
    [Fact]
    public void Stylesheets_cannot_be_added_after_the_options_are_frozen()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.Interaction.StylesheetPaths.Add("/css/authorization.css");

        options.Freeze();

        Assert.Throws<NotSupportedException>(() => options.Interaction.StylesheetPaths.Add("/css/late.css"));
        Assert.Single(options.Interaction.StylesheetPaths);
    }
}
