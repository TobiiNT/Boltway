using System.Text.Json;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Metadata;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The discovery document, asserted against the bytes rather than the object.
/// </summary>
/// <remarks>
/// Every test here parses <see cref="MetadataDocument.Json"/>. Asserting on the built record would
/// pass while the serializer wrote <c>[]</c> for an omitted array or <c>"true"</c> for a boolean —
/// and both vendors gate CIMD selection on the JSON <i>type</i> of one particular key, so the
/// difference between the object and its serialization is the difference between working and not.
/// </remarks>
public sealed class MetadataTests
{
    private static JsonElement Serialize(Action<AuthorizationServerOptions>? tweak = null)
    {
        var document = MetadataDocument.Create(Build.Options(tweak));
        return JsonDocument.Parse(document.Json.AsSpan().ToArray()).RootElement.Clone();
    }

    /// <summary>RFC 8414 §3.2: a zero-element array is omitted, never written as <c>[]</c>.</summary>
    /// <remarks>
    /// A whole-document sweep rather than a check on the one property that prompted it. The rule is
    /// about the serializer's behaviour, so a property added later is covered without anyone
    /// remembering to add it here.
    /// </remarks>
    [Fact]
    public void No_property_is_an_empty_array()
    {
        var root = Serialize();

        var empty = root.EnumerateObject()
            .Where(p => p.Value.ValueKind is JsonValueKind.Array && p.Value.GetArrayLength() == 0)
            .Select(p => p.Name)
            .ToList();

        Assert.Empty(empty);
    }

    /// <summary>No property is written as null.</summary>
    [Fact]
    public void No_property_is_null()
    {
        var root = Serialize();

        var nulls = root.EnumerateObject()
            .Where(p => p.Value.ValueKind is JsonValueKind.Null)
            .Select(p => p.Name)
            .ToList();

        Assert.Empty(nulls);
    }

    /// <summary>
    /// <c>client_id_metadata_document_supported</c> is a JSON boolean, not the string.
    /// </summary>
    /// <remarks>
    /// Gate #1 for CIMD selection by both vendors, and the string <c>"true"</c> reads to them as
    /// absent — which silently downgrades every client to whatever the fallback is.
    /// </remarks>
    [Fact]
    public void The_cimd_flag_is_a_json_boolean()
    {
        var root = Serialize();

        Assert.Equal(JsonValueKind.True, root.GetProperty("client_id_metadata_document_supported").ValueKind);
    }

    /// <summary>
    /// The two registration mechanisms are never advertised together.
    /// </summary>
    /// <remarks>
    /// N-06 / A-05. Both profiles are checked, because the failure mode is asymmetric: with both
    /// keys present a live measurement showed Claude choosing DCR, against the MCP specification's
    /// stated priority order, so the CIMD profile leaking a <c>registration_endpoint</c> silently
    /// disables the mechanism the deployment chose.
    /// </remarks>
    [Fact]
    public void Exactly_one_registration_mechanism_is_advertised()
    {
        var root = Serialize(o => o.RegistrationProfile = ClientRegistrationProfile.ClientIdMetadataDocument);

        Assert.False(root.TryGetProperty("registration_endpoint", out _));
        Assert.True(root.TryGetProperty("client_id_metadata_document_supported", out _));
    }

    /// <summary>
    /// The dynamic-registration profile cannot be selected, because <c>/register</c> does not exist.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This test used to be the second row of the theory above, asserting that the DCR profile
    /// publishes <c>registration_endpoint</c>. It does — and nothing routes <c>/register</c>, so a
    /// client that read the document and followed it got a 404. Measured on a running host, both
    /// <c>GET</c> and <c>POST</c>.
    /// </para>
    /// <para>
    /// That is the same N-06 failure as the four endpoint flags which defaulted to advertising
    /// <c>/userinfo</c>, <c>/revoke</c>, <c>/introspect</c> and <c>/logout</c> while all four 404'd.
    /// It survived that fix because it is a profile rather than a flag, and it survived
    /// <c>Every_advertised_endpoint_answers</c> because that sweep runs against the default profile.
    /// So the row that pinned it is now a row that forbids it.
    /// </para>
    /// <para>
    /// Refused at startup rather than silently downgraded to CIMD: a deployment that asked for
    /// dynamic registration wants it, and starting anyway with a different mechanism answers a
    /// question the operator did not ask.
    /// </para>
    /// </remarks>
    [Fact]
    public void The_dynamic_registration_profile_is_refused_while_register_is_not_routed()
    {
        var options = Build.Options();
        options.RegistrationProfile = ClientRegistrationProfile.DynamicRegistration;

        Assert.False(options.TryValidate(out var errors));
        Assert.Contains(errors, e => e.Contains("registration_endpoint", StringComparison.Ordinal));
    }

    /// <summary>
    /// The four OIDC booleans are written even though they are false.
    /// </summary>
    /// <remarks>
    /// <c>request_uri_parameter_supported</c> defaults to <b>true</b> in OIDC Discovery §3, so
    /// omitting it advertises a feature this server refuses. The other three are written for the
    /// same reason at one remove: silence is a claim, and it is the wrong one.
    /// </remarks>
    [Theory]
    [InlineData("claims_parameter_supported")]
    [InlineData("request_parameter_supported")]
    [InlineData("request_uri_parameter_supported")]
    [InlineData("require_request_uri_registration")]
    public void The_false_oidc_booleans_are_still_written(string property)
    {
        var root = Serialize();

        Assert.Equal(JsonValueKind.False, root.GetProperty(property).ValueKind);
    }

    /// <summary>PKCE is advertised as S256 and nothing else — never <c>plain</c>.</summary>
    [Fact]
    public void Only_s256_is_advertised_for_pkce()
    {
        var root = Serialize();

        var methods = root.GetProperty("code_challenge_methods_supported")
            .EnumerateArray()
            .Select(e => e.GetString())
            .ToList();

        Assert.Equal(["S256"], methods);
    }

    /// <summary>The implicit grant is gone, so it is not in <c>response_types_supported</c>.</summary>
    [Fact]
    public void Only_the_code_response_type_is_advertised()
    {
        var root = Serialize();

        Assert.Equal(
            ["code"],
            root.GetProperty("response_types_supported").EnumerateArray().Select(e => e.GetString()).ToList());
    }

    /// <summary>
    /// <c>none</c> is offered at the token endpoint and refused at revocation and introspection.
    /// </summary>
    /// <remarks>
    /// The asymmetry is the point. A public client has no secret to present at <c>/token</c>, and
    /// PKCE is what protects that exchange. Revocation and introspection have no equivalent: an
    /// unauthenticated caller who can revoke has a denial-of-service primitive, and one who can
    /// introspect has a token-status oracle.
    /// </remarks>
    [Fact]
    public void Unauthenticated_clients_are_offered_the_token_endpoint_and_nothing_else()
    {
        // Both endpoints turned on explicitly, because they are off by default now that neither is
        // routed — advertising them was four simultaneous N-06 violations. This test is about the
        // auth methods those keys carry *when* a deployment offers them, so it has to ask for them.
        var root = Serialize(o =>
        {
            o.RevocationEnabled = true;
            o.IntrospectionEnabled = true;
        });

        Assert.Contains("none", Strings(root, "token_endpoint_auth_methods_supported"));
        Assert.DoesNotContain("none", Strings(root, "revocation_endpoint_auth_methods_supported"));
        Assert.DoesNotContain("none", Strings(root, "introspection_endpoint_auth_methods_supported"));
    }

    /// <summary>Turning a feature off removes its key and everything that describes it.</summary>
    /// <remarks>
    /// The <c>enabled</c> half is not decoration. All four flags now default to
    /// <see langword="false"/>, so setting them to <see langword="false"/> here sets them to the
    /// value they already had — and this test would have passed against a builder that never emitted
    /// these keys under any configuration, which is a different bug wearing the same green tick.
    /// Asserting the keys appear first is what makes their absence afterwards mean something.
    /// </remarks>
    [Fact]
    public void A_disabled_endpoint_leaves_no_trace_in_the_document()
    {
        var enabled = Serialize(o =>
        {
            o.RevocationEnabled = true;
            o.IntrospectionEnabled = true;
            o.UserInfoEnabled = true;
            o.EndSessionEnabled = true;
        });

        foreach (var name in new[]
        {
            "revocation_endpoint", "revocation_endpoint_auth_methods_supported",
            "introspection_endpoint", "introspection_endpoint_auth_methods_supported",
            "userinfo_endpoint", "end_session_endpoint",
        })
        {
            Assert.True(enabled.TryGetProperty(name, out _), $"{name} should appear when enabled.");
        }

        var root = Serialize(o =>
        {
            o.RevocationEnabled = false;
            o.IntrospectionEnabled = false;
            o.UserInfoEnabled = false;
            o.EndSessionEnabled = false;
        });

        Assert.False(root.TryGetProperty("revocation_endpoint", out _));
        Assert.False(root.TryGetProperty("revocation_endpoint_auth_methods_supported", out _));
        Assert.False(root.TryGetProperty("revocation_endpoint_auth_signing_alg_values_supported", out _));
        Assert.False(root.TryGetProperty("introspection_endpoint", out _));
        Assert.False(root.TryGetProperty("introspection_endpoint_auth_methods_supported", out _));
        Assert.False(root.TryGetProperty("userinfo_endpoint", out _));
        Assert.False(root.TryGetProperty("end_session_endpoint", out _));
    }

    /// <summary>
    /// The document says nothing about DPoP, under any spelling. The authorization-server half of
    /// the D-02 tripwire.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The resource-server half is
    /// <c>ProtectedResourceMetadataEndpointTests.Optional_members_that_are_not_configured_are_absent</c>,
    /// which names <c>dpop_bound_access_tokens_required</c> and
    /// <c>dpop_signing_alg_values_supported</c>. This side names nothing and matches on the prefix
    /// instead, because the member that matters here —
    /// <c>dpop_signing_alg_values_supported</c> — has no field on
    /// <c>AuthorizationServerMetadata</c> at all, so a named assertion would be testing that a type
    /// still lacks a property somebody would have had to add. Prefix matching keeps working when
    /// they add it, and catches whatever they call it.
    /// </para>
    /// <para>
    /// D-02's seam note is the rule this enforces: <b>advertise nothing DPoP-related.</b> An
    /// advertised <c>dpop_signing_alg_values_supported</c> invites proofs this server would reject,
    /// which presents to a client as a working handshake followed by a 401 it cannot diagnose.
    /// </para>
    /// </remarks>
    [Fact]
    public void The_document_advertises_nothing_dpop_related()
    {
        var enabled = Serialize(o =>
        {
            // Every optional surface on, so the widest document this server can produce is the one
            // being searched.
            o.RevocationEnabled = true;
            o.IntrospectionEnabled = true;
            o.UserInfoEnabled = true;
            o.EndSessionEnabled = true;
        });

        var dpop = enabled
            .EnumerateObject()
            .Where(member => member.Name.StartsWith("dpop", StringComparison.OrdinalIgnoreCase))
            .Select(member => member.Name)
            .ToList();

        Assert.True(
            dpop.Count == 0,
            "The discovery document now advertises " + string.Join(", ", dpop)
            + ". D-02 defers DPoP and its seam note says to advertise nothing DPoP-related, because "
            + "an advertised algorithm list invites proofs this server would reject.");
    }

    /// <summary>Unconfigured optional URLs are absent, not empty strings.</summary>
    [Fact]
    public void Unconfigured_optional_metadata_is_absent()
    {
        var root = Serialize();

        Assert.False(root.TryGetProperty("service_documentation", out _));
        Assert.False(root.TryGetProperty("op_policy_uri", out _));
        Assert.False(root.TryGetProperty("op_tos_uri", out _));
        Assert.False(root.TryGetProperty("ui_locales_supported", out _));
        Assert.False(root.TryGetProperty("protected_resources", out _));
    }

    /// <summary>Configured optional metadata appears.</summary>
    [Fact]
    public void Configured_optional_metadata_is_present()
    {
        var root = Serialize(o =>
        {
            o.ServiceDocumentation = "https://auth.example.com/docs";
            o.PolicyUri = "https://auth.example.com/privacy";
            o.ProtectedResources.Add("https://mcp.example.com/mcp");
            o.UiLocalesSupported.Add("en-US");
        });

        Assert.Equal("https://auth.example.com/docs", root.GetProperty("service_documentation").GetString());
        Assert.Equal("https://auth.example.com/privacy", root.GetProperty("op_policy_uri").GetString());
        Assert.Equal(["https://mcp.example.com/mcp"], Strings(root, "protected_resources"));
        Assert.Equal(["en-US"], Strings(root, "ui_locales_supported"));
    }

    /// <summary>
    /// The issuer is emitted exactly as configured, and every endpoint is built from it.
    /// </summary>
    /// <remarks>
    /// N-13: this string appears in five places that must agree byte for byte, and clients compare
    /// it with Simple String Comparison. A re-serialization anywhere in the path — <c>new
    /// Uri(issuer).ToString()</c> appends a slash — makes it a different issuer.
    /// </remarks>
    [Fact]
    public void The_issuer_is_emitted_verbatim_and_prefixes_every_endpoint()
    {
        var root = Serialize();
        var issuer = root.GetProperty("issuer").GetString();

        Assert.Equal(Build.Issuer, issuer);

        foreach (var property in root.EnumerateObject())
        {
            if (!property.Name.EndsWith("_endpoint", StringComparison.Ordinal)
                && !string.Equals(property.Name, "jwks_uri", StringComparison.Ordinal))
            {
                continue;
            }

            Assert.StartsWith(issuer! + "/", property.Value.GetString()!, StringComparison.Ordinal);
        }
    }

    /// <summary>RS256 is in the ID token algorithms, because OIDC Discovery §3 requires it.</summary>
    [Fact]
    public void Rs256_is_advertised_for_id_tokens()
    {
        var root = Serialize();

        Assert.Contains("RS256", Strings(root, "id_token_signing_alg_values_supported"));
    }

    /// <summary>And nothing else, because nothing else can be minted.</summary>
    /// <remarks>
    /// This list was filled from <c>SigningAlgorithms.All</c>, which documents itself as the
    /// verifier allow-list — what the server <em>accepts</em>. <c>id_token_signing_alg_values
    /// _supported</c> is what it <em>issues</em>, and <c>TokenIssuer.MintAsync</c> asks the ring
    /// for RS256 and nothing else, so ES256 was advertised and unobtainable. A relying party
    /// configuring <c>id_token_signed_response_alg=ES256</c> out of this document rejects every
    /// token this server can produce. Accepting more than you issue is ordinary; advertising more
    /// than you issue is a promise to somebody else's code.
    /// </remarks>
    [Fact]
    public void Only_what_can_be_minted_is_advertised_for_id_tokens()
    {
        Assert.Equal(["RS256"], Strings(Serialize(), "id_token_signing_alg_values_supported"));
    }

    /// <summary>
    /// <c>client_secret_post</c> is not offered by default, because no registration path in this
    /// build produces a client that uses it.
    /// </summary>
    /// <remarks>
    /// Both stores yield <c>none</c> or <c>client_secret_basic</c> depending on whether a secret
    /// hash exists, service accounts are created <c>client_secret_basic</c> outright, and CIMD
    /// §4.1 refuses every symmetric method. So an integrator read this list, configured
    /// <c>client_secret_post</c> — the default in a great many OAuth libraries — and got
    /// <c>invalid_client</c> saying they must authenticate with a client secret while sending
    /// exactly that. N-06, the same shape as <c>form_post</c> and the four advertised endpoints
    /// with no route. A deployment whose own client store registers one turns it back on.
    /// </remarks>
    [Fact]
    public void Client_secret_post_is_not_advertised_by_default()
    {
        Assert.DoesNotContain(
            "client_secret_post", Strings(Serialize(), "token_endpoint_auth_methods_supported"));
    }

    /// <summary>
    /// <c>none</c> never appears in a signing algorithm list.
    /// </summary>
    /// <remarks>
    /// RFC 8414 §2 forbids it explicitly, and the reason is that a client that accepts <c>alg:
    /// none</c> accepts an assertion anyone can write.
    /// </remarks>
    [Fact]
    public void No_signing_algorithm_list_contains_none()
    {
        var root = Serialize();

        foreach (var property in root.EnumerateObject())
        {
            if (!property.Name.Contains("signing_alg", StringComparison.Ordinal))
            {
                continue;
            }

            Assert.DoesNotContain("none", property.Value.EnumerateArray().Select(e => e.GetString()));
        }
    }

    /// <summary>The document is deterministic: the same configuration serializes to the same bytes.</summary>
    /// <remarks>
    /// E-01 through E-06 are required to serve byte-identical bodies, and the ETag is a hash of what
    /// is sent — so a document that varied between builds would answer <c>304</c> against a body the
    /// client does not have.
    /// </remarks>
    [Fact]
    public void The_same_configuration_produces_the_same_bytes()
    {
        var first = MetadataDocument.Create(Build.Options());
        var second = MetadataDocument.Create(Build.Options());

        Assert.Equal(first.Json.AsSpan().ToArray(), second.Json.AsSpan().ToArray());
        Assert.Equal(first.ETag, second.ETag);
    }

    /// <summary>A different configuration produces a different ETag.</summary>
    /// <remarks>
    /// The control for the test above. Byte-equality is trivially satisfiable by a bug that returns
    /// a constant, and the pair together rule that out.
    /// </remarks>
    [Fact]
    public void A_changed_configuration_changes_the_etag()
    {
        var baseline = MetadataDocument.Create(Build.Options());

        // Toggled OFF, and it has been both. This read `= false` when false was the default, which
        // made the "changed" document byte-identical to the baseline and the control assert nothing;
        // it was corrected to `= true`, and then the default moved to true when /userinfo was
        // implemented, which recreated the same emptiness from the other side.
        //
        // So the rule this line has now been caught by twice: **the value has to be the opposite of
        // the default, and the default is not a constant.** If UserInfoEnabled ever defaults to
        // false again, this flips back — or better, points at whichever flag is then default-off.
        var changed = MetadataDocument.Create(Build.Options(o => o.UserInfoEnabled = false));

        Assert.NotEqual(baseline.ETag, changed.ETag);
    }

    /// <summary>Building from invalid configuration throws rather than publishing something broken.</summary>
    [Fact]
    public void An_invalid_configuration_cannot_produce_a_document()
    {
        var options = new AuthorizationServerOptions { Issuer = "http://auth.example.com" };

        var thrown = Assert.Throws<InvalidOperationException>(() => MetadataDocument.Create(options));

        Assert.Contains("https", thrown.Message, StringComparison.Ordinal);
    }

    private static List<string?> Strings(JsonElement root, string property) =>
        [.. root.GetProperty(property).EnumerateArray().Select(e => e.GetString())];
}
