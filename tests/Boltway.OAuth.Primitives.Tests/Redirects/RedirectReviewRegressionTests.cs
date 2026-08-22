using Boltway.OAuth.Primitives.Encoding;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Redirects;

namespace Boltway.OAuth.Primitives.Tests.Redirects;

/// <summary>
/// Regressions for defects found by adversarial review of the first implementation.
/// </summary>
/// <remarks>
/// Every case here matched, parsed or threw before the fix. They are kept in one file so that the
/// cost of the review is visible: this is what one pass over 8 files found, and it is the argument
/// for doing it after every step rather than at the end.
/// </remarks>
public sealed class RedirectReviewRegressionTests
{
    private static bool Reaches(string registered, string requested)
    {
        Assert.True(RegisteredRedirectUri.TryRegister(registered, out var reg, out var regError),
            $"registration of '{registered}' failed: {regError}");

        return RequestedRedirectUri.TryParse(requested, out var req, out _)
            && RedirectUriMatcher.Match(req!.Value, [reg!.Value]).Matched;
    }

    // ---------------------------------------------------------------- finding 1 (critical)

    [Theory]
    [InlineData("http://127.0.0.1:1/callback\r\n\r\n")]
    [InlineData("http://127.0.0.1:1/callback\r\n")]
    [InlineData("http://127.0.0.1:1/callback\n\n")]
    [InlineData("http://127.0.0.1:1/callback\t\r\n ")]
    [InlineData("http://127.0.0.1:1/callback ")]
    [InlineData(" http://127.0.0.1:1/callback")]
    [InlineData("\r\nhttp://127.0.0.1:1/callback")]
    public void Whitespace_and_control_characters_never_reach_a_match(string requested)
    {
        // System.Uri TRIMS leading and trailing whitespace, including CR, LF and TAB, and then
        // validates what is left. So every one of these parsed cleanly, passed every rule, and
        // matched — while RedirectMatch.RequestedValue, documented as "the value to actually
        // redirect to", still carried the CRLF. That value goes in a Location header: response
        // splitting on the authorization server's own origin.
        Assert.False(Reaches("http://127.0.0.1/callback", requested));
    }

    [Theory]
    [InlineData("https://evil.example/cb\r\n\r\n<script>")]
    [InlineData("https://evil.example/cb\r\nSet-Cookie: a=b")]
    [InlineData("https://evil.example/cb\n")]
    [InlineData("https://evil.example/cb\t")]
    [InlineData("https://evil.example/ cb")]
    public void A_control_bearing_redirect_uri_cannot_be_registered(string raw)
    {
        // Worse than the request side, because it needs no loopback and reaches the exact-match
        // path: with DCR or CIMD a client registers itself, so a client that could store a
        // CRLF-bearing redirect URI could then drive a victim through /authorize.
        Assert.False(RegisteredRedirectUri.TryRegister(raw, out _, out var error));
        Assert.Equal(RedirectUriError.Malformed, error);
    }

    // ---------------------------------------------------------------- finding 2 (high)

    [Theory]
    [InlineData("http://127.0.0.1:1/a/../callback")]
    [InlineData("http://127.0.0.1:1/./callback")]
    [InlineData("http://127.0.0.1:1/x/y/../../callback")]
    [InlineData("http://127.0.0.1:1/../callback")]
    [InlineData("http://127.0.0.1:1/a/%2e%2e/callback")]
    [InlineData("http://127.0.0.1:1/%2E%2E/callback")]
    [InlineData("http://127.0.0.1:1/%63allback")]
    [InlineData("http://127.0.0.1:1/cal%6Cback")]
    public void The_loopback_path_comparison_is_on_raw_bytes(string requested)
    {
        // The loopback branch took its path from Uri.GetComponents(Path, UriEscaped), which
        // resolves dot segments and percent-decodes unreserved characters — so all eight of these
        // arrived as "callback" and matched a registration containing none of them. The file's own
        // doc comment claimed "%2e%2e must not become ..", and it did.
        Assert.False(Reaches("http://127.0.0.1/callback", requested));
    }

    [Fact]
    public void An_empty_query_is_not_the_same_as_no_query()
    {
        Assert.False(Reaches("http://127.0.0.1/callback", "http://127.0.0.1:1/callback?"));
    }

    [Fact]
    public void The_equivalent_https_cases_were_already_safe_and_stay_safe()
    {
        // These passed before the fix too — the https path never consulted a Uri-derived value.
        // They are here so the property is asserted for both kinds rather than inferred for one.
        Assert.False(Reaches("https://claude.ai/cb", "https://claude.ai/a/%2e%2e/cb"));
        Assert.False(Reaches("https://claude.ai/cb", "https://claude.ai/%63b"));
    }

    // ---------------------------------------------------------------- finding 3 (high)

    [Fact]
    public void A_default_constructed_pair_does_not_match()
    {
        // Both types are public structs, so default(T) is constructible by anyone and Value is
        // null despite the non-nullable declaration. string.Equals(null, null, Ordinal) is true,
        // so this returned a successful Exact match — and a successful match is the capability
        // token that authorizes redirecting at all.
        Assert.False(RedirectUriMatcher.Match(default, [default]).Matched);
    }

    [Fact]
    public void A_default_registration_among_real_ones_is_skipped_not_matched()
    {
        Assert.True(RequestedRedirectUri.TryParse("https://claude.ai/cb", out var req, out _));

        Assert.False(RedirectUriMatcher.Match(req!.Value, [default]).Matched);
    }

    // ---------------------------------------------------------------- finding 4 (medium)

    [Theory]
    [InlineData("AA==")]
    [InlineData("AA=")]
    [InlineData(" AA")]
    [InlineData("AA\n")]
    [InlineData("A")]        // length % 4 == 1 encodes nothing
    [InlineData("AAAAA")]
    [InlineData("A+/A")]     // standard base64 alphabet
    public void Decode_rejects_what_encode_can_never_produce(string value)
    {
        // Four spellings of one byte is an aliasing bug waiting for a caller that keys a replay
        // table or a revocation list on the string while identity comes from the decoded bytes.
        Assert.False(Base64Url.TryDecode(value, out _));
    }

    [Fact]
    public void Decode_is_the_inverse_of_encode()
    {
        var random = new byte[64];
        System.Security.Cryptography.RandomNumberGenerator.Fill(random);

        for (var length = 1; length <= random.Length; length++)
        {
            var slice = random[..length];
            var encoded = Base64Url.Encode(slice);

            Assert.True(Base64Url.TryDecode(encoded, out var decoded), $"failed at length {length}");
            Assert.Equal(slice, decoded);
        }
    }

    // ---------------------------------------------------------------- finding 5 (medium/low)

    [Fact]
    public void Matching_against_an_unparsed_verifier_fails_closed_rather_than_throwing()
    {
        // A /token handler that compared before parsing would have returned 500 instead of the
        // invalid_grant the client needs in order to recover.
        Assert.True(CodeChallenge.TryParse(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod.S256, out var challenge));

        Assert.False(challenge.Matches(default));
    }

    // The canonical-sextet regression that used to sit here has moved to PkceTests, under
    // A_challenge_in_the_alphabet_that_is_not_canonical_base64url_is_refused. It was the one PKCE
    // test in a file about redirect URIs, so a reader asking "is canonicality checked?" looked in
    // PkceTests, found nothing, and wrote it a second time — which is how this note came to exist.

    // ---------------------------------------------------------------- finding 6 (low)

    [Theory]
    [InlineData("http.s://claude.ai/cb")]  // reads as a typo of https, was classified private-use
    [InlineData("a.b://evil.example/cb")]  // a private-use scheme must not carry an authority
    [InlineData("x.:/cb")]                 // empty label
    public void Private_use_schemes_need_two_real_labels_and_no_authority(string raw)
    {
        Assert.False(RegisteredRedirectUri.TryRegister(raw, out _, out var error));
        Assert.Equal(RedirectUriError.SchemeNotAllowed, error);
    }

    [Fact]
    public void A_public_suffix_scheme_is_accepted_and_that_is_deliberate()
    {
        // `co.uk:/cb` has two non-empty labels, so it registers. Reversed it is `uk.co`, which is
        // not a name anyone meaningfully controls — but telling that apart from `com.example`
        // (equally two labels, and a perfectly legitimate reversed domain) needs a public-suffix
        // list, which is a network dependency and a maintenance burden for no security gain here:
        // private-use schemes are matched EXACTLY, so a loose classification widens nothing. The
        // rule rejects what is malformed, not what is unwise.
        Assert.True(RegisteredRedirectUri.TryRegister("co.uk:/cb", out _, out _));
    }

    [Fact]
    public void A_genuine_private_use_scheme_still_registers()
    {
        Assert.True(RegisteredRedirectUri.TryRegister("com.example.app:/oauth2redirect", out var reg, out _));
        Assert.Equal(RedirectKind.PrivateUseScheme, reg!.Value.Kind);
    }

    [Fact]
    public void Loopback_classification_and_comparison_use_the_same_case_rule()
    {
        // Classification was OrdinalIgnoreCase while comparison was Ordinal, so an uppercase host
        // entered the loopback branch and then failed its own comparison. It failed closed, but
        // for a reason no reader could predict from the code.
        Assert.False(Reaches("http://localhost/callback", "http://LOCALHOST:1/callback"));
    }

    // ---------------------------------------------------------------- named in N-04, was missing

    [Fact]
    public void Port_zero_is_refused_on_every_loopback_host()
    {
        foreach (var host in new[] { "127.0.0.1", "localhost", "[::1]" })
        {
            Assert.False(RegisteredRedirectUri.TryRegister($"http://{host}:0/callback", out _, out var error));
            Assert.Equal(RedirectUriError.PortOutOfRange, error);
        }
    }
}
