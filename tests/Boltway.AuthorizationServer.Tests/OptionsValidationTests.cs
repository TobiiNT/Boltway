using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The startup assertions - the ones that turn a misconfiguration into a failed deploy.
/// </summary>
public sealed class OptionsValidationTests
{
    private static IReadOnlyList<string> ErrorsFrom(Action<AuthorizationServerOptions> tweak)
    {
        var options = Build.Options(tweak);
        options.TryValidate(out var errors);
        return errors;
    }

    /// <summary>
    /// Any number of locales validates here; whether they are served is decided at map time.
    /// </summary>
    /// <remarks>
    /// This used to refuse more than one, because nothing read <c>ui_locales</c> and there was no
    /// per-locale text - advertising two was a claim about selection that no mechanism backed. Both
    /// exist now, so the check moved rather than went away:
    /// <c>MapBoltwayAuthorizationServer</c> compares this list against the cultures
    /// <c>RequestLocalizationMiddleware</c> will actually honour and refuses a mismatch in either
    /// direction. Counting could never have caught the real defect, which is one advertised locale
    /// that is not served.
    /// </remarks>
    [Fact]
    public void Any_number_of_ui_locales_validates_here()
    {
        Assert.Empty(ErrorsFrom(o => o.UiLocalesSupported.Add("vi")));

        Assert.Empty(ErrorsFrom(o =>
        {
            o.UiLocalesSupported.Add("en");
            o.UiLocalesSupported.Add("vi");
        }));
    }

    [Fact]
    public void A_blank_ui_locale_is_refused()
    {
        Assert.Contains(
            ErrorsFrom(o => o.UiLocalesSupported.Add("  ")),
            e => e.Contains("blank entry", StringComparison.Ordinal));
    }

    /// <summary>A valid configuration validates, so every negative case below means something.</summary>
    [Fact]
    public void The_default_configuration_validates()
    {
        Assert.True(Build.Options().TryValidate(out var errors), string.Join("; ", errors));
    }

    /// <summary>
    /// Every problem is reported, not just the first.
    /// </summary>
    /// <remarks>
    /// A-12. Fixing a misconfiguration one restart at a time is minutes per iteration on a real
    /// deployment, and the operator has no way to know how many are left.
    /// </remarks>
    [Fact]
    public void All_the_problems_are_reported_at_once()
    {
        var options = new AuthorizationServerOptions { Issuer = "http://auth.example.com/tenant/" };
        options.AccessTokenLifetime = TimeSpan.FromDays(7);

        options.TryValidate(out var errors);

        Assert.True(errors.Count >= 3, "Expected the issuer, the scopes and the lifetime to all be reported: "
            + string.Join(" | ", errors));
    }

    /// <summary>The issuer must be https.</summary>
    [Fact]
    public void A_plaintext_issuer_is_refused()
    {
        Assert.Contains(ErrorsFrom(o => o.Issuer = "http://auth.example.com"), e => e.Contains("https", StringComparison.Ordinal));
    }

    /// <summary>
    /// A trailing slash is refused, not trimmed.
    /// </summary>
    /// <remarks>
    /// Trimming is a normalization, and clients are forbidden from normalizing the issuer - so the
    /// operator who wrote the slash would see a different string in the metadata than the one they
    /// configured, which is the exact surprise the type exists to prevent.
    /// </remarks>
    [Fact]
    public void A_trailing_slash_on_the_issuer_is_refused()
    {
        var errors = ErrorsFrom(o => o.Issuer = "https://auth.example.com/");

        Assert.Contains(errors, e => e.Contains("slash", StringComparison.Ordinal));
    }

    /// <summary>
    /// A path-bearing issuer is refused with the reason spelled out.
    /// </summary>
    /// <remarks>
    /// A product requirement rather than an RFC one: RFC 8414 §3 inserts the well-known segment
    /// before the issuer path and OIDC Discovery §4.1 appends it after, so a path-bearing issuer has
    /// to serve four discovery URLs that clients probe in an order none of them agree on.
    /// </remarks>
    [Fact]
    public void A_path_bearing_issuer_is_refused()
    {
        var errors = ErrorsFrom(o => o.Issuer = "https://auth.example.com/tenant1");

        Assert.Contains(errors, e => e.Contains("path", StringComparison.Ordinal));
    }

    /// <summary>An issuer with a query or fragment is refused. RFC 8414 §2.</summary>
    [Theory]
    [InlineData("https://auth.example.com?tenant=1")]
    [InlineData("https://auth.example.com#frag")]
    public void An_issuer_with_a_query_or_fragment_is_refused(string issuer)
    {
        Assert.NotEmpty(ErrorsFrom(o => o.Issuer = issuer));
    }

    /// <summary>
    /// A scope with whitespace is refused, and the message names the offending codepoint.
    /// </summary>
    /// <remarks>
    /// A-13, and the position matters more than the refusal. <c>story:read </c> and
    /// <c>story:read</c> are different scopes because every comparison is literal, and a console
    /// renders them identically - so "invalid scope" alone sends an operator hunting for a
    /// difference their terminal will not show them.
    /// </remarks>
    [Fact]
    public void A_scope_with_a_trailing_space_names_the_character_and_its_position()
    {
        var errors = ErrorsFrom(o => o.ScopesSupported.Add("story:read "));

        var error = Assert.Single(errors, e => e.Contains("story:read", StringComparison.Ordinal));
        Assert.Contains("space", error, StringComparison.Ordinal);
        Assert.Contains("position 10", error, StringComparison.Ordinal);
    }

    /// <summary>
    /// <c>offline_access</c> must be advertised or no refresh token is ever requested.
    /// </summary>
    /// <remarks>
    /// Claude appends it to the authorization request only when the metadata lists it. Without it
    /// every connection ends when the first access token expires, and nothing in any log says why -
    /// which is why this is a boot failure rather than a warning.
    /// </remarks>
    [Fact]
    public void Offline_access_is_required()
    {
        var options = new AuthorizationServerOptions { Issuer = Build.Issuer };
        options.ScopesSupported.Add("openid");
        options.ScopesSupported.Add("mcp:tools");
        options.RefreshTokenDerivationKey = Build.DerivationKey;

        options.TryValidate(out var errors);

        Assert.Contains(errors, e => e.Contains("offline_access", StringComparison.Ordinal));
    }

    /// <summary><c>openid</c> is required because this server publishes an OP metadata document.</summary>
    [Fact]
    public void Openid_is_required()
    {
        var options = new AuthorizationServerOptions { Issuer = Build.Issuer };
        options.ScopesSupported.Add("offline_access");

        options.TryValidate(out var errors);

        Assert.Contains(errors, e => e.Contains("openid", StringComparison.Ordinal));
    }

    /// <summary>A duplicated scope is refused rather than deduplicated.</summary>
    [Fact]
    public void A_duplicated_scope_is_refused()
    {
        Assert.Contains(
            ErrorsFrom(o => o.ScopesSupported.Add("mcp:tools")),
            e => e.Contains("more than once", StringComparison.Ordinal));
    }

    /// <summary>
    /// The access-token lifetime has a floor and a ceiling, and both are explained.
    /// </summary>
    /// <remarks>
    /// The floor exists because a client that refreshes up to five minutes early refreshes
    /// continuously below it. The ceiling exists because a resource server validating offline never
    /// asks whether a token still stands, so the lifetime <i>is</i> the revocation lag.
    /// </remarks>
    [Theory]
    [InlineData(4)]
    [InlineData(60 * 25)]
    public void An_access_token_lifetime_outside_the_range_is_refused(int minutes)
    {
        Assert.Contains(
            ErrorsFrom(o => o.AccessTokenLifetime = TimeSpan.FromMinutes(minutes)),
            e => e.Contains("AccessTokenLifetime", StringComparison.Ordinal));
    }

    /// <summary>Both ends of the permitted range are accepted, so the boundary is where it is claimed.</summary>
    [Fact]
    public void The_boundaries_of_the_lifetime_range_are_accepted()
    {
        Assert.True(Build.Options(o => o.AccessTokenLifetime = AuthorizationServerOptions.MinimumAccessTokenLifetime)
            .TryValidate(out _));

        Assert.True(Build.Options(o => o.AccessTokenLifetime = AuthorizationServerOptions.MaximumAccessTokenLifetime)
            .TryValidate(out _));
    }

    /// <summary>OAuth 2.1 §4.1.2 recommends at most ten minutes for an authorization code.</summary>
    [Fact]
    public void An_over_long_authorization_code_lifetime_is_refused()
    {
        Assert.Contains(
            ErrorsFrom(o => o.AuthorizationCodeLifetime = TimeSpan.FromMinutes(11)),
            e => e.Contains("AuthorizationCodeLifetime", StringComparison.Ordinal));
    }

    /// <summary>A refresh token that expires before the access token it renews is refused.</summary>
    [Fact]
    public void A_refresh_token_shorter_than_an_access_token_is_refused()
    {
        Assert.Contains(
            ErrorsFrom(o => o.RefreshTokenLifetime = TimeSpan.FromMinutes(5)),
            e => e.Contains("RefreshTokenLifetime", StringComparison.Ordinal));
    }

    /// <summary>A grant this server has no handler for cannot be advertised.</summary>
    /// <remarks>
    /// <para>
    /// This proved the property for a name nobody would ever type. It did not hold for the two names
    /// somebody plausibly would: <c>client_credentials</c> and
    /// <c>urn:ietf:params:oauth:grant-type:jwt-bearer</c> were both in the accepted list with no arm
    /// in the token endpoint's dispatch, so enabling either advertised it and then refused it at
    /// runtime with <c>unsupported_grant_type</c>. The options file claimed the opposite about
    /// itself two hundred lines up. See <c>Every_advertised_grant_has_a_handler</c>, which pins it
    /// from the other side.
    /// </para>
    /// <para>
    /// <c>client_credentials</c> has since left this list, in the only way a name is allowed to:
    /// <see cref="ClientCredentialsGrant"/> exists and the dispatch switch has an arm for it. The
    /// name being here was never the point - the property is that a name with no handler is refused,
    /// and it is still pinned by the three that remain. Moving one out because somebody wanted it
    /// advertised, without writing the handler, is the failure this test exists to catch.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("urn:example:magic")]
    [InlineData("urn:ietf:params:oauth:grant-type:jwt-bearer")]
    [InlineData("password")]
    public void A_grant_with_no_handler_is_refused(string grantType)
    {
        var errors = ErrorsFrom(o => o.GrantTypesSupported.Add(grantType));

        Assert.Contains(errors, e => e.Contains(grantType, StringComparison.Ordinal));
    }

    /// <summary>The authorization code grant cannot be turned off.</summary>
    [Fact]
    public void Removing_the_authorization_code_grant_is_refused()
    {
        var errors = ErrorsFrom(o =>
        {
            o.GrantTypesSupported.Clear();
            o.GrantTypesSupported.Add("client_credentials");
        });

        Assert.Contains(errors, e => e.Contains("authorization_code", StringComparison.Ordinal));
    }

    /// <summary>
    /// An empty token-endpoint auth method list is refused.
    /// </summary>
    /// <remarks>
    /// RFC 8414 §2 defaults an omitted list to <c>["client_secret_basic"]</c>, which refuses every
    /// public client - including both vendors' MCP clients. Emitting nothing is not neutral.
    /// </remarks>
    [Fact]
    public void An_empty_auth_method_list_is_refused()
    {
        Assert.Contains(
            ErrorsFrom(o => o.TokenEndpointAuthMethods.Clear()),
            e => e.Contains("client_secret_basic", StringComparison.Ordinal));
    }

    /// <summary>An unspecified registration profile is refused rather than defaulted at boot.</summary>
    [Fact]
    public void An_unspecified_registration_profile_is_refused()
    {
        Assert.Contains(
            ErrorsFrom(o => o.RegistrationProfile = ClientRegistrationProfile.Unspecified),
            e => e.Contains("RegistrationProfile", StringComparison.Ordinal));
    }

    /// <summary>An optional URL that is not https is refused.</summary>
    [Fact]
    public void A_plaintext_optional_url_is_refused()
    {
        Assert.Contains(
            ErrorsFrom(o => o.PolicyUri = "http://auth.example.com/privacy"),
            e => e.Contains("PolicyUri", StringComparison.Ordinal));
    }

    /// <summary>
    /// Registration throws at wire-up time, not at the first request.
    /// </summary>
    /// <remarks>
    /// The difference is operational. A deferred validation turns a bad issuer into a 500 on the
    /// first client request - minutes after the deploy looked green, and attributed to the client.
    /// </remarks>
    [Fact]
    public void Registration_fails_the_host_immediately()
    {
        var services = new ServiceCollection();

        var thrown = Assert.Throws<AuthorizationServerConfigurationException>(
            () => services.AddBoltwayAuthorizationServer(o => o.Issuer = "http://nope"));

        Assert.NotEmpty(thrown.Errors);
    }

    /// <summary>A valid registration wires up the document and the options.</summary>
    [Fact]
    public void A_valid_registration_resolves_the_document()
    {
        var services = new ServiceCollection();
        services.AddBoltwayAuthorizationServer(o =>
        {
            o.Issuer = Build.Issuer;
            o.ScopesSupported.Add("openid");
            o.ScopesSupported.Add("offline_access");
            o.ScopesSupported.Add("mcp:tools");
                        o.RefreshTokenDerivationKey = Build.DerivationKey;
        });

        using var provider = services.BuildServiceProvider();

        Assert.Equal(Build.Issuer, provider.GetRequiredService<Metadata.MetadataDocument>().Metadata.Issuer);
        Assert.Equal(
            ClientAuthMethod.None,
            provider.GetRequiredService<AuthorizationServerOptions>().TokenEndpointAuthMethods[0]);
    }
}
