using System.Net;
using Boltway.AuthorizationServer.Interaction;
using Microsoft.AspNetCore.Http;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Three small rules about text and addresses taken from a request, each a regression.
/// </summary>
public sealed class InteractionTextHygieneTests
{
    /// <summary>
    /// A control character is removed from the one-line device description, not turned into a gap.
    /// </summary>
    /// <remarks>
    /// The comment above the loop always said "removed rather than replaced by a space", and the
    /// code set the pending space anyway. Tab and newline are whitespace and still fold to one.
    /// </remarks>
    [Fact]
    public void A_control_character_is_removed_and_whitespace_still_folds() =>
        Assert.Equal("Agent/1 build", ApprovingDevice.DescribeOnOneLine("Agent\u0001\u0002/1\t\n build"));

    /// <summary>
    /// A truncated client name never ends in half a surrogate pair.
    /// </summary>
    /// <remarks>
    /// Cutting a UTF-16 string at a fixed index can split an emoji, and a lone high surrogate before
    /// the ellipsis renders as a replacement character - on the consent page, in the client's name.
    /// </remarks>
    [Fact]
    public void A_truncated_client_name_does_not_split_a_surrogate_pair()
    {
        var cut = ConsentModelBuilder.MaxClientNameLength - 1;
        var name = new string('a', cut - 1) + "\U0001F600" + new string('b', 10);
        var client = Build.Client() with { ClientName = name };

        var safe = ConsentModelBuilder.SafeName(client)!;

        Assert.EndsWith("…", safe, StringComparison.Ordinal);
        Assert.False(char.IsHighSurrogate(safe[^2]));
        Assert.Equal(new string('a', cut - 1) + "…", safe);
    }

    /// <summary>
    /// An IPv4 address that reached the server as IPv4-mapped IPv6 shares the plain IPv4 bucket.
    /// </summary>
    /// <remarks>
    /// A dual-stack socket reports <c>::ffff:192.0.2.1</c>; folded as IPv6 to its /64, every IPv4
    /// caller behind that listener landed in one bucket, and the per-source limit became global.
    /// </remarks>
    [Fact]
    public void An_ipv4_mapped_address_is_bucketed_as_ipv4()
    {
        static string Key(string address)
        {
            var http = new DefaultHttpContext();
            http.Connection.RemoteIpAddress = IPAddress.Parse(address);
            return LoginThrottle.DefaultSourceKey(http);
        }

        Assert.Equal(Key("192.0.2.1"), Key("::ffff:192.0.2.1"));
        Assert.NotEqual(Key("::ffff:192.0.2.1"), Key("::ffff:192.0.2.2"));
    }
}
