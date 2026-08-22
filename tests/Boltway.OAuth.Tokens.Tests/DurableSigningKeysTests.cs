using System.Security.Cryptography;
using Boltway.OAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Boltway.OAuth.Tokens.Tests;

/// <summary>
/// Reading a key ring out of a secret. Every test here is a way a deployment can come up
/// holding keys that look fine and sign tokens nobody can verify — which surfaces to a user
/// as <c>invalid_token</c> on a session that worked a minute ago, and reads as their fault.
/// </summary>
public sealed class DurableSigningKeysTests
{
    private static string Pem() => RSA.Create(3072).ExportPkcs8PrivateKeyPem();

    private static string Entry(string kid, string state = "active", string? pem = null, string alg = "RS256") =>
        $$"""{"kid":"{{kid}}","alg":"{{alg}}","state":"{{state}}","pem":{{System.Text.Json.JsonSerializer.Serialize(pem ?? Pem())}}}""";

    private static string Ring(params string[] entries) => "[" + string.Join(",", entries) + "]";

    [Fact]
    public void A_key_survives_the_round_trip_and_keeps_its_identifier()
    {
        var keys = DurableSigningKeys.Parse(Ring(Entry("2026-08")));

        var key = Assert.Single(keys);
        Assert.Equal("2026-08", key.Handle.Kid);
        Assert.Equal(SigningKeyState.Active, key.State);
        Assert.Equal(SigningAlgorithm.RS256, key.Handle.Algorithm);

        // The identifier has to reach the key material too: the validator matches on the
        // token's `kid` header with TryAllIssuerSigningKeys = false, so an unlabelled key
        // matches nothing and every signature fails as though the key were absent.
        Assert.Equal("2026-08", key.Handle.Key.KeyId);
    }

    [Fact]
    public void The_same_secret_produces_a_key_that_verifies_what_the_previous_process_signed()
    {
        // The whole point. Two parses of one secret are two restarts of one server, and a
        // token minted before the restart has to still verify after it.
        var secret = Ring(Entry("2026-08"));

        var before = DurableSigningKeys.Parse(secret).Single().Handle;
        var after = DurableSigningKeys.Parse(secret).Single().Handle;

        var payload = System.Text.Encoding.UTF8.GetBytes("a token");
        var signature = ((RsaSecurityKey)before.Key).Rsa!.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        Assert.True(((RsaSecurityKey)after.Key).Rsa!.VerifyData(
            payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void A_ring_with_nothing_active_is_refused_at_parse_rather_than_at_the_first_sign_in()
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => DurableSigningKeys.Parse(Ring(Entry("next", "pending"))));

        // The ring would throw too, but only once something asked it to sign — by which time
        // the server has started, passed its health check and been sent traffic.
        Assert.Contains("No signing key is `active`", error.Message, StringComparison.Ordinal);
        Assert.Contains("next=pending", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_ring_active_for_the_wrong_algorithm_is_refused_at_parse_too()
    {
        // Active, published, and unable to sign anything this server issues. It used to parse:
        // the server started, served a JWKS full of EC keys, passed its health probe, was sent
        // traffic, and then answered every token request with an uncaught exception from inside
        // the minter — three hops from the configuration that caused it.
        var error = Assert.Throws<InvalidOperationException>(() => DurableSigningKeys.Parse(
            Ring(Entry("es-1", alg: "ES256", pem: ECDsa.Create(ECCurve.NamedCurves.nistP256).ExportPkcs8PrivateKeyPem()))));

        Assert.Contains("No active RS256 signing key", error.Message, StringComparison.Ordinal);

        // Names what is there, not only what is missing: the whole failure is that `active` was
        // true and the algorithm was the thing that was wrong.
        Assert.Contains("es-1=es256", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_ES256_key_beside_an_active_RS256_one_is_welcome()
    {
        // ES256 is not unwelcome in the ring — the verifier accepts it, and holding a key the
        // verifier accepts is what makes a rotation across algorithms possible one day. The rule
        // is only that something has to be able to sign what this server issues today.
        var keys = DurableSigningKeys.Parse(Ring(
            Entry("2026-08"),
            Entry("es-1", alg: "ES256", pem: ECDsa.Create(ECCurve.NamedCurves.nistP256).ExportPkcs8PrivateKeyPem())));

        Assert.Equal(2, keys.Count);
    }

    [Fact]
    public void A_rotation_in_flight_parses_with_all_three_phases()
    {
        var keys = DurableSigningKeys.Parse(Ring(
            Entry("old", "retiring"), Entry("current", "active"), Entry("next", "pending")));

        Assert.Equal(3, keys.Count);
        Assert.Equal(
            [SigningKeyState.Retiring, SigningKeyState.Active, SigningKeyState.Pending],
            keys.Select(k => k.State));
    }

    [Fact]
    public void Two_keys_with_one_identifier_are_refused_rather_than_one_shadowing_the_other()
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => DurableSigningKeys.Parse(Ring(Entry("same"), Entry("same", "pending"))));

        Assert.Contains("share the `kid`", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_key_with_no_identifier_is_refused()
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => DurableSigningKeys.Parse($$"""[{"alg":"RS256","state":"active","pem":{{System.Text.Json.JsonSerializer.Serialize(Pem())}}}]"""));

        Assert.Contains("no `kid`", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_retired_key_is_removed_from_the_secret_rather_than_marked()
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => DurableSigningKeys.Parse(Ring(Entry("gone", "retired"), Entry("current"))));

        // Carrying a retired key in the secret invites promoting it back by mistake, and a
        // key that has been out of JWKS is one whose compromise nobody would notice.
        Assert.Contains("removed from the secret rather than marked", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_pem_that_lost_its_line_endings_still_works()
    {
        // Measured, against the intuition. The obvious worry about a multi-line secret in an
        // environment variable is that the newlines are eaten — they are, routinely, and
        // ImportFromPem does not care. Asserting it here so nobody spends an afternoon on it.
        var flattened = Pem().Replace("\n", string.Empty, StringComparison.Ordinal);
        var crlf = Pem().Replace("\n", "\r\n", StringComparison.Ordinal);

        Assert.Single(DurableSigningKeys.Parse(Ring(Entry("flat", pem: flattened))));
        Assert.Single(DurableSigningKeys.Parse(Ring(Entry("crlf", pem: crlf))));
    }

    [Fact]
    public void A_pem_that_lost_its_header_or_its_tail_says_which_to_look_for()
    {
        var pem = Pem();
        var headerless = string.Join(string.Empty, pem.Split('\n')[1..^2]);
        var truncated = pem[..(pem.Length / 2)];

        foreach (var broken in new[] { headerless, truncated })
        {
            var error = Assert.Throws<InvalidOperationException>(
                () => DurableSigningKeys.Parse(Ring(Entry("broken", pem: broken))));

            Assert.Contains("-----BEGIN", error.Message, StringComparison.Ordinal);
            Assert.Contains("line endings are not the problem", error.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void The_generated_entry_is_a_ring_this_can_read_back()
    {
        var ring = "[" + DurableSigningKeys.NewRsaEntry("2026-08") + "]";
        var key = Assert.Single(DurableSigningKeys.Parse(ring));

        Assert.Equal("2026-08", key.Handle.Kid);
        Assert.Equal(SigningKeyState.Active, key.State);

        // 3072, not 2048. SigningKeyHandle enforces a floor; this picks a size that stays
        // above it as the floor moves rather than sitting on it.
        Assert.True(((RsaSecurityKey)key.Handle.Key).Rsa!.KeySize >= 3072);
    }

    [Fact]
    public void A_generated_pending_key_is_the_first_step_of_a_rotation_and_is_not_active_yet()
    {
        var ring = "[" + DurableSigningKeys.NewRsaEntry("current") + "," +
                   DurableSigningKeys.NewRsaEntry("next", SigningKeyState.Pending) + "]";

        var keys = DurableSigningKeys.Parse(ring);
        Assert.Equal(SigningKeyState.Pending, keys.Single(k => k.Handle.Kid == "next").State);
        Assert.Null(keys.Single(k => k.Handle.Kid == "next").ActivatedAt);
    }
}
