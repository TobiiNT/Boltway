using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Diagnostics;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The doctor's shape and the one failure branch a test can reach.
/// </summary>
/// <remarks>
/// <para>
/// From the mutation run: 72 survivors on <c>ConfigurationDoctor.cs</c>, 55 of them string
/// mutations and 17 behavioural. Reading them one at a time produced an uncomfortable but useful
/// answer - <b>twelve of the seventeen are equivalent mutants</b>, because the branches they change
/// cannot be reached through the public API at all. They are enumerated at the bottom of this file
/// with the reason each is unreachable, because "no test kills it" and "no input can produce it"
/// look identical in a report and mean opposite things.
/// </para>
/// <para>
/// The five that were real gaps are covered here.
/// </para>
/// </remarks>
public sealed class ConfigurationDoctorCoverageTests
{
    private static DoctorCheck Check(IReadOnlyList<DoctorCheck> checks, string id) =>
        Assert.Single(checks, c => string.Equals(c.Id, id, StringComparison.Ordinal));

    [Fact]
    public void Run_refuses_a_null_options()
    {
        // Run is public API. The guard turns a NullReferenceException several frames deep into an
        // ArgumentNullException naming the parameter, which is the difference between a caller
        // fixing their call and a caller reading this file.
        Assert.Throws<ArgumentNullException>(() => ConfigurationDoctor.Run(null!, TestKeys.Ring()));
    }

    /// <summary>
    /// A healthy run reports exactly these six checks - no more and, more to the point, no fewer.
    /// </summary>
    /// <remarks>
    /// Every <c>checks.Add(...)</c> in <c>Run</c> could be deleted without a test failing.
    /// <c>A_healthy_configuration_passes</c> asserts every check is a Pass, which stays true when a
    /// check disappears; <c>Every_check_is_addressable</c> asserts the ids are distinct, which also
    /// stays true. A doctor silently missing a check is the failure mode the tool exists to prevent,
    /// and it was the one thing nothing asserted.
    /// </remarks>
    [Fact]
    public void A_healthy_run_reports_exactly_the_expected_checks()
    {
        var checks = ConfigurationDoctor.Run(Build.Options(), TestKeys.Ring());

        Assert.Equal(
            ["config", "issuer-agreement", "metadata", "registration-profile", "scope-descriptions", "signing-keys"],
            checks.Select(c => c.Id).Order(StringComparer.Ordinal));
    }

    /// <summary>
    /// When the configuration fails, every dependent check is reported as NotMeasured.
    /// </summary>
    /// <remarks>
    /// <c>Checks_hidden_by_a_configuration_failure_are_not_measured</c> asserts two of the three and
    /// omits <c>issuer-agreement</c>, so deleting its <c>NotMeasured</c> line survived. The check
    /// vanishing entirely is worse than it being wrong: a summary one check short reads as a clean
    /// bill of health for something nobody looked at.
    /// </remarks>
    [Fact]
    public void A_configuration_failure_leaves_no_check_unaccounted_for()
    {
        var checks = ConfigurationDoctor.Run(
            new AuthorizationServerOptions { Issuer = "http://nope" }, TestKeys.Ring());

        Assert.Equal(
            ["config", "issuer-agreement", "metadata", "registration-profile", "scope-descriptions", "signing-keys"],
            checks.Select(c => c.Id).Order(StringComparer.Ordinal));

        Assert.Equal(DoctorStatus.NotMeasured, Check(checks, "issuer-agreement").Status);
        Assert.Equal(DoctorStatus.NotMeasured, Check(checks, "metadata").Status);
        Assert.Equal(DoctorStatus.NotMeasured, Check(checks, "registration-profile").Status);

        // scope-descriptions depends on the configuration for a subtler reason than the three
        // above: the list it reads is populated *by* TryValidate, so a failed run may never have
        // reached the scope parse and an empty list would read as "everything is described".
        Assert.Equal(DoctorStatus.NotMeasured, Check(checks, "scope-descriptions").Status);
    }

    /// <summary>
    /// An access-token lifetime the key ring cannot outlive warns on the key check.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>arithmeticOk ? Pass : Warn</c> in <c>CheckKeyRing</c>, mutated to always-Pass, survived.
    /// Reaching the Warn branch takes a detail that is easy to miss: <c>CheckKeyRing</c> is added
    /// <b>outside</b> the configured/not-configured branch, so it runs even when the configuration
    /// did not validate. With a valid configuration it cannot fail - <c>AccessTokenLifetime</c> is
    /// capped at 24 hours and <c>RetentionAfterRetirement</c> defaults to exactly 24 hours, so
    /// <c>Retention &lt; lifetime</c> is never true.
    /// </para>
    /// <para>
    /// A lifetime past the cap is therefore the only way in, and it is a real deployment: an
    /// operator who sets 48 hours gets told by the config check that the setting is out of range,
    /// and by this check that the ring would retire a key while tokens signed with it are still
    /// live. Both facts are worth having, and only the first was tested.
    /// </para>
    /// </remarks>
    [Fact]
    public void A_lifetime_the_ring_cannot_outlive_warns_on_the_key_check()
    {
        var options = Build.Options(o => o.AccessTokenLifetime = TimeSpan.FromHours(48));

        var checks = ConfigurationDoctor.Run(options, TestKeys.Ring());

        Assert.Equal(DoctorStatus.Fail, Check(checks, "config").Status);
        // Warn, not Fail. The ring can still sign and publish; what it cannot do is retain a
        // retired key for as long as tokens signed with it stay valid, which degrades verification
        // rather than stopping it. Asserted as written rather than as assumed - the first version
        // of this test expected Fail and was wrong about the server, not the other way round.
        Assert.Equal(DoctorStatus.Warn, Check(checks, "signing-keys").Status);
    }

    [Fact]
    public void A_lifetime_inside_the_cap_passes_the_key_check()
    {
        // The control. Without it, asserting Warn above would pass against a key check that always
        // warns, and the ternary would be pinned in the wrong direction.
        var options = Build.Options(o => o.AccessTokenLifetime = TimeSpan.FromHours(24));

        var checks = ConfigurationDoctor.Run(options, TestKeys.Ring());

        Assert.Equal(DoctorStatus.Pass, Check(checks, "config").Status);
        Assert.Equal(DoctorStatus.Pass, Check(checks, "signing-keys").Status);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The twelve equivalent mutants, and why no test can kill them
    // ─────────────────────────────────────────────────────────────────────────
    //
    // CheckIssuerAgreement - ten of the twelve. Lines 180-187 are eight Check(url, name) calls,
    //   line 193 is the strays.Add inside them (reported NoCoverage, which is the giveaway), and
    //   line 197 is `strays.Count == 0 ? Pass : Warn`.
    //
    //   Every URL in the document is built by `string Url(string path) => issuer + path`, and every
    //   path is a `const string` on AuthorizationServerPaths. No configuration can make an endpoint
    //   fail to start with the issuer, so `strays` is always empty, the Warn branch is unreachable,
    //   and deleting any individual Check() changes nothing observable.
    //
    //   That is worth saying plainly: this check cannot fail as the server is currently built. It
    //   is a guard against a future change that makes endpoint paths configurable - which the
    //   comment above it half-implies is already possible ("a deployment where they diverge"), and
    //   it is not. Left in place rather than deleted, because deleting a check is a product call;
    //   recorded here so the next mutation run does not reopen it.
    //
    // CheckRegistrationProfile - lines 152 and 166. `!hasRegistration && !hasCimd` and
    //   `hasCimd ? "…Metadata Document." : "Dynamic client registration."`. ClientRegistrationProfile
    //   has three values and options validation rejects two of them: Unspecified ("Choose
    //   ClientIdMetadataDocument") and DynamicRegistration ("nothing routes /register"). Reaching
    //   these lines requires a configuration that validated, so hasCimd is always true and hasRegistration
    //   always false. The existing test's own remark says as much - "When DCR ships, this becomes a
    //   theory again and that test inverts."
}
