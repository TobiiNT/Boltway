using System.Net;
using System.Net.Sockets;

namespace Boltway.OAuth.Net;

/// <summary>
/// Which IP addresses this server refuses to connect to. RFC 6890 and friends.
/// </summary>
/// <remarks>
/// <para>
/// The SSRF blocklist. Everything an attacker would point a fetch at that is not a globally
/// routable host on the public internet: loopback, the RFC 1918 private ranges, link-local — which
/// is where <c>169.254.169.254</c> lives, the cloud instance-metadata endpoint that hands out
/// credentials to anything that asks — carrier-grade NAT, multicast, and the IPv6 equivalents of
/// each.
/// </para>
/// <para>
/// <b>IPv4-mapped IPv6 is unwrapped first.</b> <c>::ffff:169.254.169.254</c> is the metadata
/// endpoint written as an IPv6 address, and a checker that only knows IPv6 ranges sees a value in
/// none of them and says yes. This is the single most commonly missed entry in a blocklist of this
/// kind.
/// </para>
/// </remarks>
public static class SpecialUseAddresses
{
    /// <summary>
    /// Whether this address is one the server must never connect to.
    /// </summary>
    public static bool IsBlocked(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        // Unwrap ::ffff:a.b.c.d to a.b.c.d BEFORE any range test. Without this,
        // ::ffff:169.254.169.254 reaches the cloud metadata service through the IPv6 path.
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => IsBlockedV4(address),
            AddressFamily.InterNetworkV6 => IsBlockedV6(address),
            // Anything that is neither is not something we know how to reason about.
            _ => true,
        };
    }

    /// <summary>
    /// Whether this address is one no legitimate answer for a public name could be.
    /// </summary>
    /// <param name="address">The address a host name resolved to.</param>
    /// <exception cref="ArgumentNullException"><paramref name="address" /> is null.</exception>
    /// <remarks>
    /// <para>
    /// Link-local: <c>169.254.0.0/16</c>, <c>fe80::/10</c>, and the encoded forms of the first. It
    /// is where <c>169.254.169.254</c> lives, and it is the one part of the blocklist with no
    /// innocent explanation — a name in public DNS resolving into it is not a filtered resolver,
    /// not split-horizon DNS, and not a host somebody has not configured yet.
    /// </para>
    /// <para>
    /// <strong>This does not decide whether to connect.</strong> <see cref="IsBlocked" /> decides
    /// that and refuses every special-use address either way. What this decides is what the server
    /// is entitled to <em>say</em> about the answer, and whether the event is worth keeping a client
    /// broken over — because everything else in the blocklist is ambiguous and this is not.
    /// </para>
    /// <para>
    /// The rest of the list looks the same from here whatever produced it. <c>0.0.0.0</c> and
    /// <c>127.0.0.1</c> are what a DNS blocklist answers with, what an unconfigured host answers
    /// with, <em>and</em> live targets — measured on 2026-08-26, Linux 6.18: connecting to
    /// <c>0.0.0.0</c> reaches a service bound to <c>127.0.0.1</c>, so a sinkhole answer is not a
    /// harmless one. The RFC 1918 ranges are what split-horizon DNS answers with for a name a
    /// company hosts internally, which is ordinary. None of those can be told apart from an attack
    /// by looking at one lookup, and this method does not pretend otherwise.
    /// </para>
    /// </remarks>
    public static bool IsLinkLocal(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            Span<byte> v4 = stackalloc byte[4];
            return address.TryWriteBytes(v4, out _) && v4[0] is 169 && v4[1] is 254;
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return false;
        }

        Span<byte> b = stackalloc byte[16];
        if (!address.TryWriteBytes(b, out _))
        {
            return false;
        }

        // fe80::/10.
        if (b[0] is 0xfe && (b[1] & 0xc0) is 0x80)
        {
            return true;
        }

        // 2002::/16 6to4 carries an IPv4 destination in bytes 2..5, and ::a.b.c.d - the deprecated
        // IPv4-compatible form of RFC 4291 §2.5.5.1 - carries one in the last four. Both are how
        // 169.254.169.254 is written when somebody does not want it recognised, which is the same
        // reason IsBlocked unwraps ::ffff: before any range test.
        if (b[0] is 0x20 && b[1] is 0x02)
        {
            return b[2] is 169 && b[3] is 254;
        }

        var compatible = true;
        for (var i = 0; i < 12; i++)
        {
            if (b[i] is not 0)
            {
                compatible = false;
                break;
            }
        }

        return compatible && b[12] is 169 && b[13] is 254;
    }

    private static bool IsBlockedV4(IPAddress address)
    {
        Span<byte> b = stackalloc byte[4];
        if (!address.TryWriteBytes(b, out _))
        {
            return true;
        }

        return b[0] switch
        {
            0 => true,                                  // 0.0.0.0/8      "this network"
            10 => true,                                 // 10.0.0.0/8     RFC 1918
            127 => true,                                // 127.0.0.0/8    loopback
            100 when b[1] is >= 64 and <= 127 => true,  // 100.64.0.0/10  RFC 6598 carrier-grade NAT
            169 when b[1] is 254 => true,               // 169.254.0.0/16 link-local, incl. cloud metadata
            172 when b[1] is >= 16 and <= 31 => true,   // 172.16.0.0/12  RFC 1918
            192 when b[1] is 0 && b[2] is 0 => true,    // 192.0.0.0/24   IETF protocol assignments
            192 when b[1] is 0 && b[2] is 2 => true,    // 192.0.2.0/24   TEST-NET-1
            192 when b[1] is 168 => true,               // 192.168.0.0/16 RFC 1918
            192 when b[1] is 88 && b[2] is 99 => true,  // 192.88.99.0/24 6to4 relay anycast
            198 when b[1] is 18 or 19 => true,          // 198.18.0.0/15  benchmarking
            198 when b[1] is 51 && b[2] is 100 => true, // 198.51.100.0/24 TEST-NET-2
            203 when b[1] is 0 && b[2] is 113 => true,  // 203.0.113.0/24 TEST-NET-3
            >= 224 => true,                             // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved,
                                                        // and 255.255.255.255 broadcast
            _ => false,
        };
    }

    /// <summary>
    /// IPv6, as an allowlist of global unicast rather than a blocklist of specials.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Default-deny, and the inversion is the fix rather than a style choice. The first version of
    /// this method enumerated special ranges, and an audit measured sixteen it did not cover —
    /// including two with real teeth: <c>2002:7f00:1::</c> and <c>2002:a9fe:a9fe::</c>, which are
    /// 6to4-encoded <c>127.0.0.1</c> and <c>169.254.169.254</c>, and <c>::169.254.169.254</c>, the
    /// deprecated IPv4-<i>compatible</i> form (RFC 4291 §2.5.5.1) that is the sibling of the
    /// <c>::ffff:</c> form the code already unwrapped.
    /// </para>
    /// <para>
    /// A blocklist of this shape loses to registry updates by construction: every new special-use
    /// assignment is a hole until someone notices. <c>2000::/3</c> is the entire global unicast
    /// space, so refusing everything outside it covers the sixteen misses and every future
    /// assignment outside that block, in one line.
    /// </para>
    /// </remarks>
    private static bool IsBlockedV6(IPAddress address)
    {
        Span<byte> b = stackalloc byte[16];
        if (!address.TryWriteBytes(b, out _))
        {
            return true;
        }

        // Everything outside 2000::/3 global unicast. This alone covers loopback, ::, the
        // IPv4-compatible ::a.b.c.d form, 64:ff9b::/96 NAT64, 100::/64, fc00::/7 unique local,
        // fe80::/10 link-local, fec0::/10 site-local, ff00::/8 multicast, and 5f00::/16.
        if (b[0] is < 0x20 or > 0x3f)
        {
            return true;
        }

        // 2001::/23 — the IETF protocol assignments block: Teredo, PCP anycast, NAT64 discovery,
        // AMT, ORCHIDv2 and the rest all live inside it.
        if (b[0] is 0x20 && b[1] is 0x01 && (b[2] & 0xfe) is 0)
        {
            return true;
        }

        // 2001:db8::/32 documentation.
        if (b[0] is 0x20 && b[1] is 0x01 && b[2] is 0x0d && b[3] is 0xb8)
        {
            return true;
        }

        // 2002::/16 — 6to4. Encodes an IPv4 destination in the address, which is the same argument
        // that makes NAT64 dangerous: 2002:7f00:1:: is 127.0.0.1 and 2002:a9fe:a9fe:: is the cloud
        // metadata endpoint.
        if (b[0] is 0x20 && b[1] is 0x02)
        {
            return true;
        }

        // 3fff::/20 — documentation, RFC 9637.
        if (b[0] is 0x3f && b[1] is 0xff && (b[2] & 0xf0) is 0)
        {
            return true;
        }

        return false;
    }
}
