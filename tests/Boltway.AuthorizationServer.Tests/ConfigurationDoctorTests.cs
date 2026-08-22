using System.Security.Cryptography;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.OAuth.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>The doctor, which is what an operator has instead of a debugger.</summary>
public sealed class ConfigurationDoctorTests
{
    private static DoctorCheck Check(IReadOnlyList<DoctorCheck> checks, string id) =>
        Assert.Single(checks, c => string.Equals(c.Id, id, StringComparison.Ordinal));

    /// <summary>A healthy deployment passes every check.</summary>
    [Fact]
    public void A_healthy_configuration_passes()
    {
        var checks = ConfigurationDoctor.Run(Build.Options(), TestKeys.Ring());

        Assert.All(checks, c => Assert.Equal(DoctorStatus.Pass, c.Status));
    }

    /// <summary>
    /// A configuration failure reports the dependent checks as NotMeasured, never as Pass.
    /// </summary>
    /// <remarks>
    /// The distinction this whole enum exists for. A check that could not run, rendered green, is a
    /// claim nobody made — and from that point on it is indistinguishable in every summary from a
    /// check that actually ran.
    /// </remarks>
    [Fact]
    public void Checks_hidden_by_a_configuration_failure_are_not_measured()
    {
        var checks = ConfigurationDoctor.Run(new AuthorizationServerOptions { Issuer = "http://nope" }, TestKeys.Ring());

        Assert.Equal(DoctorStatus.Fail, Check(checks, "config").Status);
        Assert.Equal(DoctorStatus.NotMeasured, Check(checks, "metadata").Status);
        Assert.Equal(DoctorStatus.NotMeasured, Check(checks, "registration-profile").Status);
        Assert.DoesNotContain(checks, c => c.Status is DoctorStatus.Pass && c.Id is not "signing-keys");
    }

    /// <summary>An absent key ring is NotMeasured, not a failure and not a pass.</summary>
    /// <remarks>
    /// Failing would be wrong — a caller that did not supply a ring has not told the doctor
    /// anything about its keys — and passing would be a lie about the one thing that makes every
    /// token verifiable.
    /// </remarks>
    [Fact]
    public void An_absent_key_ring_is_not_measured()
    {
        var checks = ConfigurationDoctor.Run(Build.Options(), keyRing: null);

        Assert.Equal(DoctorStatus.NotMeasured, Check(checks, "signing-keys").Status);
    }

    /// <summary>An empty key ring fails, because the JWKS would be empty.</summary>
    [Fact]
    public void An_empty_key_ring_fails()
    {
        var checks = ConfigurationDoctor.Run(Build.Options(), new SigningKeyRing([]));

        var check = Check(checks, "signing-keys");
        Assert.Equal(DoctorStatus.Fail, check.Status);
        Assert.Contains("empty", check.Detail, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A ring whose only key is still pending fails rather than silently signing with it.
    /// </summary>
    /// <remarks>
    /// The ring refuses to fall back to a pending key, and this is the check that surfaces the
    /// refusal at startup rather than at the first token request. Signing with a key nobody has
    /// fetched produces tokens that fail verification everywhere — a quieter failure than not
    /// issuing one.
    /// </remarks>
    [Fact]
    public void A_ring_with_no_active_key_fails()
    {
        var rsa = RSA.Create(2048);
        var handle = new SigningKeyHandle("pending", SigningAlgorithm.RS256, new RsaSecurityKey(rsa));
        var ring = new SigningKeyRing([new ManagedSigningKey(handle, SigningKeyState.Pending, DateTimeOffset.UtcNow)]);

        var check = Check(ConfigurationDoctor.Run(Build.Options(), ring), "signing-keys");

        Assert.Equal(DoctorStatus.Fail, check.Status);
        Assert.Contains("RS256", check.Detail, StringComparison.Ordinal);
    }

    /// <summary>The profile check names the mechanism in use.</summary>
    /// <remarks>
    /// One profile rather than a theory over two, because dynamic registration is refused by options
    /// validation while <c>/register</c> is not routed — advertising <c>registration_endpoint</c>
    /// against a 404 is N-06 reached through configuration. See
    /// <c>MetadataTests.The_dynamic_registration_profile_is_refused_while_register_is_not_routed</c>.
    /// When DCR ships, this becomes a theory again and that test inverts.
    /// </remarks>
    [Fact]
    public void The_registration_profile_check_names_the_mechanism()
    {
        var checks = ConfigurationDoctor.Run(
            Build.Options(o => o.RegistrationProfile = ClientRegistrationProfile.ClientIdMetadataDocument),
            TestKeys.Ring());

        var check = Check(checks, "registration-profile");
        Assert.Equal(DoctorStatus.Pass, check.Status);
        Assert.Contains("Metadata", check.Detail, StringComparison.Ordinal);
    }

    /// <summary>The failure detail says what to fix, not merely that something is wrong.</summary>
    /// <remarks>
    /// A-12: <c>curl</c> and this output together have to be enough. "Invalid configuration" sends
    /// an operator to read source they do not have.
    /// </remarks>
    [Fact]
    public void A_failure_detail_names_the_setting_and_the_fix()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com/" };
        options.ScopesSupported.Add("openid");
        options.ScopesSupported.Add("offline_access");

        var check = Check(ConfigurationDoctor.Run(options, TestKeys.Ring()), "config");

        Assert.Equal(DoctorStatus.Fail, check.Status);
        Assert.Contains("slash", check.Detail, StringComparison.Ordinal);
        Assert.Contains("Configure it without the slash", check.Detail, StringComparison.Ordinal);
    }

    /// <summary>Every check has a stable id and a non-empty detail, so a script can key on it.</summary>
    [Fact]
    public void Every_check_is_addressable()
    {
        var checks = ConfigurationDoctor.Run(Build.Options(), TestKeys.Ring());

        Assert.Equal(checks.Select(c => c.Id).Distinct(StringComparer.Ordinal).Count(), checks.Count);
        Assert.All(checks, c => Assert.False(string.IsNullOrWhiteSpace(c.Detail)));
        Assert.All(checks, c => Assert.False(string.IsNullOrWhiteSpace(c.Title)));
    }
}
