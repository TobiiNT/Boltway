using Boltway.OAuth.Primitives.Encoding;

namespace Boltway.OAuth.Primitives.Tests.Encoding;

/// <summary>One spelling per byte string.</summary>
public sealed class Base64UrlTests
{
    [Fact]
    public void The_canonical_spelling_decodes()
    {
        Assert.True(Base64Url.TryDecode("AA", out var bytes));
        Assert.Equal([0x00], bytes);
    }

    /// <summary>
    /// Non-zero unused trailing bits are refused.
    /// </summary>
    /// <remarks>
    /// Not a regression test: measured 2026-11-03 on .NET 10, the runtime decoder already refuses
    /// these, which is why <c>TryDecode</c> has no check of its own. Pinned because the claim that
    /// it does not was made in review, and a later runtime or a different decoder that let "AB"
    /// decode like "AA" would give one value two spellings - a comparison on the encoded form and
    /// one on the bytes would then disagree.
    /// </remarks>
    [Theory]
    [InlineData("AB")]
    [InlineData("AAB")]
    public void A_non_canonical_spelling_is_refused(string value) =>
        Assert.False(Base64Url.TryDecode(value, out _));
}
