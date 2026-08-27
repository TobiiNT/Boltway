using Boltway.AuthorizationServer.Interaction;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Turning a <c>User-Agent</c> into something a person recognises.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every one of these headers is a real one</b>, because the thing under test is a pile of
/// heuristics over a string format that has been lying about itself since 1994 - every browser here
/// claims to be Mozilla, Chrome claims to be Safari, and Edge claims to be both. Invented headers
/// would test the matcher against the shape somebody imagined rather than the shape it will meet.
/// </para>
/// <para>
/// <b>The ordering tests are the ones that matter.</b> Reversing any two lines in either matcher
/// still passes a test that only checks Firefox, and reports most of a real fleet as Safari.
/// </para>
/// </remarks>
public sealed class ApprovingDeviceTests
{
    [Theory]
    [InlineData(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
        + "Chrome/140.0.0.0 Safari/537.36",
        "Chrome on macOS")]
    [InlineData(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        + "Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
        "Edge on Windows")]
    [InlineData(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0",
        "Firefox on macOS")]
    [InlineData(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
        + "Version/18.0 Mobile/15E148 Safari/604.1",
        "Safari on iPhone")]
    [InlineData(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
        + "Version/17.6 Safari/605.1.15",
        "Safari on macOS")]
    [InlineData(
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
        + "Chrome/140.0.0.0 Mobile Safari/537.36",
        "Chrome on Android")]
    [InlineData(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "Chrome on Linux")]
    public void A_familiar_browser_is_named(string userAgent, string expected) =>
        Assert.Equal(expected, ApprovingDevice.Describe(userAgent));

    /// <summary>
    /// Edge is Edge, and Chrome is Chrome, though both headers name Chrome and Safari.
    /// </summary>
    /// <remarks>
    /// Stated on its own because it is the specific regression the ordering in <c>Browser</c> exists
    /// for. Both of these headers contain <c>Chrome/</c> and <c>Safari/</c>; only the first also
    /// contains <c>Edg/</c>, and only testing that first tells them apart.
    /// </remarks>
    [Fact]
    public void Edge_is_not_reported_as_chrome_and_chrome_is_not_reported_as_safari()
    {
        const string Edge =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            + "Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0";

        const string Chrome =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            + "Chrome/140.0.0.0 Safari/537.36";

        Assert.Equal("Edge on Windows", ApprovingDevice.Describe(Edge));
        Assert.Equal("Chrome on Windows", ApprovingDevice.Describe(Chrome));
    }

    /// <summary>An iPhone is an iPhone, though its header also says Mac OS X.</summary>
    /// <remarks>
    /// The platform half of the same trap: every iOS header carries <c>like Mac OS X</c>, so testing
    /// <c>Macintosh</c> first would report a phone as a laptop - on the page whose entire job is
    /// telling somebody which of their devices approved something.
    /// </remarks>
    [Fact]
    public void An_iphone_is_not_reported_as_a_mac()
    {
        const string IPhone =
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
            + "Version/18.0 Mobile/15E148 Safari/604.1";

        Assert.Equal("Safari on iPhone", ApprovingDevice.Describe(IPhone));
    }

    /// <summary>
    /// An unfamiliar header comes back as itself rather than as a guess.
    /// </summary>
    /// <remarks>
    /// Ugly and true. "Unknown device" would be neither, and on a page listing two sessions the raw
    /// string still tells them apart while a placeholder does not.
    /// </remarks>
    [Theory]
    [InlineData("curl/8.7.1")]
    [InlineData("Mozilla/5.0 (compatible; SomeNewBrowser/1.0)")]
    [InlineData("Chrome/140.0.0.0")]
    public void An_unfamiliar_header_is_returned_as_itself(string userAgent) =>
        Assert.Equal(userAgent, ApprovingDevice.Describe(userAgent));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Nothing_recorded_describes_as_nothing(string? userAgent) =>
        Assert.Null(ApprovingDevice.Describe(userAgent));
}
