using System.Globalization;
using Boltway.Identity.Passwords;
using Konscious.Security.Cryptography;

namespace Boltway.Identity.Tests;

public sealed class Argon2idPasswordHasherTests
{
    /// <summary>
    /// Cheap parameters, so a test that only cares about the encoding does not pay for 19 MiB.
    /// </summary>
    /// <remarks>
    /// Named rather than inlined so nobody reads a passing test as evidence that <b>these</b> are the
    /// shipped costs. <see cref="The_shipped_defaults_are_the_owasp_configuration"/> is what pins
    /// those, and it is the only test that asserts about them.
    /// </remarks>
    private static Argon2idParameters Cheap => new()
    {
        MemoryKiB = 64,
        Iterations = 1,
        Parallelism = 1,
    };

    private static Argon2idPasswordHasher Hasher() => new(Cheap);

    // ------------------------------------------------------- is this actually Argon2id

    /// <summary>
    /// The library computes RFC 9106's Argon2id test vector.
    /// </summary>
    /// <remarks>
    /// The known-answer test for the whole choice. Everything else in this file would pass against a
    /// hasher that did something plausible and wrong - a round trip verifies against itself, and
    /// "wrong password fails" holds for any deterministic function - so without this, "we use
    /// Argon2id" rests on the package name. RFC 9106 §5.3, with the secret and associated-data
    /// inputs the vector specifies; the hasher itself uses neither, which is why this test drives
    /// the library directly rather than through <see cref="Argon2idPasswordHasher"/>.
    /// </remarks>
    [Fact]
    public void The_library_matches_the_rfc_9106_argon2id_test_vector()
    {
        using var argon2 = new Argon2id(Filled(32, 0x01))
        {
            Salt = Filled(16, 0x02),
            KnownSecret = Filled(8, 0x03),
            AssociatedData = Filled(12, 0x04),
            MemorySize = 32,
            Iterations = 3,
            DegreeOfParallelism = 4,
        };

        Assert.Equal(
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
            Convert.ToHexString(argon2.GetBytes(32)).ToLowerInvariant());
    }

    private static byte[] Filled(int length, byte value) => [.. Enumerable.Repeat(value, length)];

    // ------------------------------------------------------- the parameters

    /// <summary>
    /// The shipped cost is the OWASP configuration the comment cites, and a 128-bit salt.
    /// </summary>
    /// <remarks>
    /// A test rather than trust, because the number in the comment and the number in the code are
    /// two things that can drift apart, and the comment is the only place the provenance lives.
    /// </remarks>
    [Fact]
    public void The_shipped_defaults_are_the_owasp_configuration()
    {
        var defaults = Argon2idParameters.Default;

        Assert.Equal(19456, defaults.MemoryKiB);
        Assert.Equal(2, defaults.Iterations);
        Assert.Equal(1, defaults.Parallelism);
        Assert.Equal(16, defaults.SaltBytes);
        Assert.Equal(32, defaults.HashBytes);
    }

    [Theory]
    [InlineData(0, 1, 1)]                 // no memory
    [InlineData(4, 1, 1)]                 // less than 8 * p
    [InlineData(1024 * 1024 + 1, 1, 1)]   // past the allocation ceiling
    [InlineData(64, 0, 1)]                // no iterations
    [InlineData(64, 33, 1)]               // past the iteration ceiling
    [InlineData(64, 1, 0)]                // no lanes
    [InlineData(64, 1, 17)]               // past the lane ceiling
    public void A_configuration_outside_the_bounds_is_refused_at_construction(int memory, int iterations, int lanes)
    {
        // At construction, not at the first login. A hasher that accepts a nonsense cost and fails
        // when someone signs in has moved the failure from a deploy to a user.
        Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2idPasswordHasher(new Argon2idParameters
        {
            MemoryKiB = memory,
            Iterations = iterations,
            Parallelism = lanes,
        }));
    }

    // ------------------------------------------------------- hashing and verifying

    [Fact]
    public void A_password_verifies_against_its_own_hash()
    {
        var hasher = Hasher();

        Assert.True(hasher.Verify("correct horse battery staple", hasher.Hash("correct horse battery staple")));
    }

    [Fact]
    public void A_wrong_password_does_not_verify()
    {
        var hasher = Hasher();

        Assert.False(hasher.Verify("wrong", hasher.Hash("correct horse battery staple")));
    }

    [Fact]
    public void Two_hashes_of_one_password_differ_because_the_salt_does()
    {
        // Equal hashes would mean no salt, and no salt means one rainbow table covers every
        // deployment at once. The property is visible from outside precisely because the salt
        // travels in the encoded string.
        var hasher = Hasher();

        Assert.NotEqual(hasher.Hash("same"), hasher.Hash("same"), StringComparer.Ordinal);
    }

    [Fact]
    public void The_encoded_hash_carries_its_own_parameters()
    {
        var encoded = Hasher().Hash("pw");

        Assert.StartsWith("$argon2id$v=19$m=64,t=1,p=1$", encoded, StringComparison.Ordinal);

        // Six fields, of which the last two are the salt and the tag. The shape matters because it
        // is what another Argon2 implementation reads.
        Assert.Equal(6, encoded.Split('$').Length);
    }

    /// <summary>
    /// Verification uses the parameters in the stored hash, not the ones configured now.
    /// </summary>
    /// <remarks>
    /// The single most common way a password upgrade path is botched, stated as a test: the deploy
    /// that raises the cost invalidates every password already stored, and the symptom is every
    /// existing user unable to sign in with a correct password. Reading the cost from the stored
    /// string is the only thing that prevents it - and a hasher that read its own configuration
    /// instead would pass every other test in this file.
    /// </remarks>
    [Fact]
    public void A_hash_made_under_the_old_cost_still_verifies_after_the_cost_is_raised()
    {
        var old = new Argon2idPasswordHasher(Cheap);
        var stored = old.Hash("pw");

        var raised = new Argon2idPasswordHasher(Cheap with { MemoryKiB = 256, Iterations = 2 });

        Assert.True(raised.Verify("pw", stored));
        Assert.False(raised.Verify("not pw", stored));
    }

    [Fact]
    public void A_hash_from_the_current_cost_does_not_need_rehashing()
    {
        var hasher = Hasher();

        Assert.False(hasher.NeedsRehash(hasher.Hash("pw")));
        Assert.False(hasher.VerifyForUpgrade("pw", hasher.Hash("pw")).NeedsRehash);
    }

    [Theory]
    [InlineData(128, 1, 1)]   // more memory than configured
    [InlineData(64, 2, 1)]    // more iterations
    public void A_hash_stronger_than_the_current_cost_is_left_alone(int memory, int iterations, int lanes)
    {
        // Rehashing a stronger hash down to the configured cost would spend the upgrade mechanism on
        // weakening stored passwords. An operator who lowers the cost gets no mass downgrade.
        var stronger = new Argon2idPasswordHasher(new Argon2idParameters
        {
            MemoryKiB = memory,
            Iterations = iterations,
            Parallelism = lanes,
        });

        Assert.False(Hasher().NeedsRehash(stronger.Hash("pw")));
    }

    [Theory]
    [InlineData(32, 1, 1)]   // less memory
    [InlineData(64, 1, 2)]   // a different lane count, in either direction
    public void A_hash_behind_the_current_cost_is_reported_for_rehashing(int memory, int iterations, int lanes)
    {
        var weaker = new Argon2idPasswordHasher(new Argon2idParameters
        {
            MemoryKiB = memory,
            Iterations = iterations,
            Parallelism = lanes,
        });

        var stored = weaker.Hash("pw");
        var current = new Argon2idPasswordHasher(Cheap);

        // Still verifies - the upgrade is transparent, not a lockout - and is flagged in the same
        // call, because the only moment a rehash is possible is the moment the plaintext has just
        // been confirmed.
        var result = current.VerifyForUpgrade("pw", stored);

        Assert.True(result.Succeeded);
        Assert.True(result.NeedsRehash);
        Assert.True(current.NeedsRehash(stored));
    }

    [Fact]
    public void A_rehash_after_an_upgrade_lands_on_the_new_cost()
    {
        // The end of the upgrade story: verify under the old cost, re-hash under the new one, and
        // the result no longer asks to be upgraded.
        var stored = new Argon2idPasswordHasher(Cheap with { MemoryKiB = 32 }).Hash("pw");
        var current = Hasher();

        Assert.True(current.VerifyForUpgrade("pw", stored) is { Succeeded: true, NeedsRehash: true });

        var upgraded = current.Hash("pw");

        Assert.False(current.NeedsRehash(upgraded));
        Assert.True(current.Verify("pw", upgraded));
    }

    // ------------------------------------------------------- malformed stored values

    [Theory]
    [InlineData("")]
    [InlineData("not a hash")]
    [InlineData("$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")]
    [InlineData("$argon2id$v=16$m=64,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")]
    [InlineData("$argon2id$v=19$t=1,m=64,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")]
    [InlineData("$argon2id$v=19$m=64,t=1,p=1$$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")]
    [InlineData("$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")]
    public void A_stored_value_we_cannot_read_fails_the_login_rather_than_the_request(string stored)
    {
        // Fail closed, and without an exception. This value comes from a database column reached by
        // an unauthenticated POST, so an exception here is a 500 anyone can provoke - and the shape
        // of the failure would itself distinguish "this row is odd" from "wrong password".
        var hasher = Hasher();

        Assert.False(hasher.Verify("pw", stored));
        Assert.False(hasher.VerifyForUpgrade("pw", stored).Succeeded);

        // And it is reported as needing replacement, because it is certainly not the current format.
        Assert.True(hasher.NeedsRehash(stored));
    }

    [Fact]
    public void A_stored_value_declaring_a_ruinous_cost_is_refused_without_allocating_it()
    {
        // The reason Verify's parameters are bounded even though they come from our own writer: they
        // arrive from storage, and storage is not a trust boundary this code gets to assume.
        // 16 GiB would be an out-of-memory on the login path rather than a failed login.
        var stored = string.Create(
            CultureInfo.InvariantCulture,
            $"$argon2id$v=19$m={16 * 1024 * 1024},t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g");

        Assert.False(Hasher().Verify("pw", stored));
    }

    // ------------------------------------------------------- leaks

    [Fact]
    public void Nothing_about_the_hasher_prints_a_password()
    {
        // N-16's spirit: the password is not in ToString, and not in the exception a bad parameter
        // raises. There is no field holding it - Derive turns it into bytes and drops them - so this
        // pins the absence rather than a redaction.
        var hasher = Hasher();

        Assert.DoesNotContain("hunter2", hasher.ToString() ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", hasher.Hash("hunter2"), StringComparison.Ordinal);

        var thrown = Record.Exception(() => new Argon2idPasswordHasher(Cheap with { Iterations = 0 }));

        Assert.NotNull(thrown);
        Assert.DoesNotContain("hunter2", thrown.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void A_null_password_is_a_bug_at_the_caller_not_a_failed_login()
    {
        var hasher = Hasher();

        Assert.Throws<ArgumentNullException>(() => hasher.Hash(null!));
        Assert.Throws<ArgumentNullException>(() => hasher.Verify(null!, hasher.Hash("pw")));
    }

    /// <summary>
    /// An empty password fails the login rather than the request.
    /// </summary>
    /// <remarks>
    /// Found by <c>LoginFlowTests</c>, not by reading: the library throws
    /// <see cref="ArgumentException"/> - "Argon2 needs a password set" - on a zero-length input, and
    /// the login endpoint does not catch it. Posting an empty password field was a 500 that any
    /// unauthenticated request could provoke at will, and whose shape differed from every ordinary
    /// failed login.
    /// </remarks>
    [Fact]
    public void An_empty_password_is_refused_at_both_ends_without_throwing_on_the_login_path()
    {
        var hasher = Hasher();
        var stored = hasher.Hash("pw");

        // Verify: false, and no exception. This is the path an HTTP request reaches.
        Assert.False(hasher.Verify(string.Empty, stored));
        Assert.False(hasher.VerifyForUpgrade(string.Empty, stored).Succeeded);

        // Hash: a throw, because storing one is a registration-policy failure. It is what makes the
        // answer above sound - no hash this type produced can be of an empty password, so refusing
        // to verify one cannot be a false negative.
        Assert.Throws<ArgumentException>(() => hasher.Hash(string.Empty));
    }

    [Fact]
    public void An_empty_password_is_refused_the_same_way_whatever_the_stored_value_is()
    {
        // The short-circuit must not become a second oracle. It is keyed on the password the caller
        // sent, so it has to answer identically for a real hash, an unreadable one and an empty one
        // - otherwise it distinguishes accounts again, one layer down.
        var hasher = Hasher();

        Assert.False(hasher.Verify(string.Empty, hasher.Hash("pw")));
        Assert.False(hasher.Verify(string.Empty, "not a hash at all"));
        Assert.False(hasher.Verify(string.Empty, string.Empty));
    }

    /// <summary>
    /// A password is hashed as its UTF-8 bytes, with no Unicode normalization.
    /// </summary>
    /// <remarks>
    /// Pinned because it is a limitation rather than a feature, and an unpinned limitation gets
    /// "fixed" by someone adding a <c>Normalize()</c> call - which would invalidate every stored
    /// hash of a password containing a composable character. <c>InvariantGlobalization</c> is set
    /// tree-wide, so normalization is not available here anyway; this records the consequence.
    /// </remarks>
    [Fact]
    public void Two_compositions_of_one_character_are_two_different_passwords()
    {
        // Written as escapes rather than as literal text. Typed literally, an editor or a git
        // filter that normalises the file would make the two strings identical, and the test
        // would pass while asserting nothing.
        const string Precomposed = "caf\u00E9";        // e-acute as one code point
        const string Decomposed = "cafe\u0301";        // e followed by a combining acute

        var hasher = Hasher();

        Assert.False(hasher.Verify(Decomposed, hasher.Hash(Precomposed)));
    }
}
