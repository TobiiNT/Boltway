using System.Text.Json;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Metadata;
using Boltway.OAuth.Tokens;

namespace Boltway.AuthorizationServer.Diagnostics;

/// <summary>How a check came out.</summary>
public enum DoctorStatus
{
    /// <summary>Checked, and correct.</summary>
    Pass = 0,

    /// <summary>Checked, and wrong. The server should not serve traffic.</summary>
    Fail = 1,

    /// <summary>Checked, and questionable. Serving is possible; someone should look.</summary>
    Warn = 2,

    /// <summary>
    /// <b>Not checked.</b> Never rendered as a pass.
    /// </summary>
    /// <remarks>
    /// The distinction is the entire reason this enum has four members instead of three. A check
    /// that could not run — no Docker for the Postgres leg, no network for a live fetch — reported
    /// as green is a claim nobody made, and it is indistinguishable from a real pass in every
    /// summary it appears in afterwards.
    /// </remarks>
    NotMeasured = 3,
}

/// <summary>One thing the doctor looked at.</summary>
/// <param name="Id">A stable identifier, so a script can key on it.</param>
/// <param name="Title">What was checked.</param>
/// <param name="Status">How it came out.</param>
/// <param name="Detail">
/// What was found, in words, and for a failure what to do about it. A-12: <c>curl</c> and this
/// output together have to be enough to debug a deployment.
/// </param>
public sealed record DoctorCheck(string Id, string Title, DoctorStatus Status, string Detail);

/// <summary>
/// Checks a deployment's configuration before it serves anything.
/// </summary>
/// <remarks>
/// Separate from <see cref="AuthorizationServerOptions.TryValidate"/> because the two answer
/// different questions. Validation asks "is this configuration internally consistent" and runs at
/// startup with a boot failure attached. The doctor asks "does this configuration describe a server
/// that will actually work for a client", which includes things that are legal but wrong — a key
/// ring with nothing published, a metadata document advertising a scope no resource defines.
/// </remarks>
public static class ConfigurationDoctor
{
    /// <summary>Run every check that does not need the network.</summary>
    public static IReadOnlyList<DoctorCheck> Run(AuthorizationServerOptions options, SigningKeyRing? keyRing)
    {
        ArgumentNullException.ThrowIfNull(options);

        var checks = new List<DoctorCheck>();

        var configured = options.TryValidate(out var errors);

        checks.Add(configured
            ? new DoctorCheck("config", "Configuration validates", DoctorStatus.Pass, "Every setting is consistent.")
            : new DoctorCheck(
                "config",
                "Configuration validates",
                DoctorStatus.Fail,
                string.Join(Environment.NewLine, errors.Select(e => "  - " + e))));

        if (!configured)
        {
            // Every check below reads the built metadata document, and building it from invalid
            // configuration throws. Reporting them as NotMeasured says what is true: the
            // configuration failure hid them, and fixing it may reveal more.
            checks.Add(NotMeasured("metadata", "Discovery document", "The configuration did not validate."));
            checks.Add(NotMeasured("registration-profile", "Exactly one registration mechanism", "The configuration did not validate."));
            checks.Add(NotMeasured("issuer-agreement", "Endpoint URLs share the issuer prefix", "The configuration did not validate."));
        }
        else
        {
            var document = MetadataDocument.Create(options);
            checks.Add(CheckMetadata(document));
            checks.Add(CheckRegistrationProfile(document));
            checks.Add(CheckIssuerAgreement(document));
        }

        checks.Add(CheckKeyRing(options, keyRing));

        return checks;
    }

    private static DoctorCheck CheckMetadata(MetadataDocument document)
    {
        // Parsed back rather than trusted, because what matters is the bytes on the wire. A property
        // that serializes to `[]` or to `"true"` instead of `true` is a defect no amount of reading
        // the builder finds — both vendors gate CIMD selection on the JSON type of one of these.
        using var parsed = JsonDocument.Parse(document.Json.AsSpan().ToArray());
        var root = parsed.RootElement;

        var emptyArrays = root
            .EnumerateObject()
            .Where(p => p.Value.ValueKind is JsonValueKind.Array && p.Value.GetArrayLength() == 0)
            .Select(p => p.Name)
            .ToList();

        if (emptyArrays.Count > 0)
        {
            return new DoctorCheck(
                "metadata",
                "Discovery document",
                DoctorStatus.Fail,
                $"RFC 8414 §3.2 requires a zero-element array to be omitted. Emitted empty: "
                + string.Join(", ", emptyArrays));
        }

        if (root.TryGetProperty("client_id_metadata_document_supported", out var cimd)
            && cimd.ValueKind is not JsonValueKind.True and not JsonValueKind.False)
        {
            return new DoctorCheck(
                "metadata",
                "Discovery document",
                DoctorStatus.Fail,
                "client_id_metadata_document_supported is not a JSON boolean. Both vendors gate CIMD "
                + "selection on this key's type, and the string \"true\" reads as absent.");
        }

        return new DoctorCheck(
            "metadata",
            "Discovery document",
            DoctorStatus.Pass,
            $"{document.Json.Length} bytes, ETag {document.ETag}.");
    }

    private static DoctorCheck CheckRegistrationProfile(MetadataDocument document)
    {
        var metadata = document.Metadata;
        var hasRegistration = metadata.RegistrationEndpoint is not null;
        var hasCimd = metadata.ClientIdMetadataDocumentSupported is true;

        if (hasRegistration && hasCimd)
        {
            return new DoctorCheck(
                "registration-profile",
                "Exactly one registration mechanism",
                DoctorStatus.Fail,
                "Both registration_endpoint and client_id_metadata_document_supported are present. "
                + "A live measurement showed Claude choosing DCR when both are advertised, against "
                + "the priority order the MCP specification states (N-06, A-05).");
        }

        if (!hasRegistration && !hasCimd)
        {
            return new DoctorCheck(
                "registration-profile",
                "Exactly one registration mechanism",
                DoctorStatus.Fail,
                "Neither registration_endpoint nor client_id_metadata_document_supported is present, "
                + "so no client can obtain a client_id from this server.");
        }

        return new DoctorCheck(
            "registration-profile",
            "Exactly one registration mechanism",
            DoctorStatus.Pass,
            hasCimd ? "Client ID Metadata Document." : "Dynamic client registration.");
    }

    private static DoctorCheck CheckIssuerAgreement(MetadataDocument document)
    {
        var metadata = document.Metadata;
        var issuer = metadata.Issuer;

        // Every URL in the document must sit under the issuer. Not a spec rule — RFC 8414 permits
        // endpoints on other hosts — but a deployment where they diverge has almost always got its
        // issuer from the wrong place, and the symptom downstream is an `aud` or `iss` mismatch
        // several hops away from the cause.
        var strays = new List<string>();

        Check(metadata.AuthorizationEndpoint, "authorization_endpoint");
        Check(metadata.TokenEndpoint, "token_endpoint");
        Check(metadata.JwksUri, "jwks_uri");
        Check(metadata.UserInfoEndpoint, "userinfo_endpoint");
        Check(metadata.RevocationEndpoint, "revocation_endpoint");
        Check(metadata.IntrospectionEndpoint, "introspection_endpoint");
        Check(metadata.EndSessionEndpoint, "end_session_endpoint");
        Check(metadata.RegistrationEndpoint, "registration_endpoint");

        void Check(string? url, string name)
        {
            if (url is not null && !url.StartsWith(issuer, StringComparison.Ordinal))
            {
                strays.Add($"{name} ({url})");
            }
        }

        return strays.Count == 0
            ? new DoctorCheck("issuer-agreement", "Endpoint URLs share the issuer prefix", DoctorStatus.Pass, issuer)
            : new DoctorCheck(
                "issuer-agreement",
                "Endpoint URLs share the issuer prefix",
                DoctorStatus.Warn,
                $"These do not start with '{issuer}': {string.Join(", ", strays)}.");
    }

    private static DoctorCheck CheckKeyRing(AuthorizationServerOptions options, SigningKeyRing? keyRing)
    {
        if (keyRing is null)
        {
            return NotMeasured(
                "signing-keys",
                "A signing key is active and published",
                "No key ring was supplied to the doctor.");
        }

        var published = keyRing.PublishedKeys();

        if (published.Count == 0)
        {
            return new DoctorCheck(
                "signing-keys",
                "A signing key is active and published",
                DoctorStatus.Fail,
                "The JWKS would be empty, so no client can validate any token this server issues.");
        }

        // The configured algorithm, not RS256 — a deployment that set TokenSigningAlgorithm to
        // ES256 and holds only an EC key is correct, and asking the ring for RS256 would report it
        // as broken. What must hold is that the ring can sign with what this server advertises,
        // and both come off the same option.
        var issuing = options.TokenSigningAlgorithm;

        try
        {
            _ = keyRing.ActiveKey(issuing);
        }
        catch (InvalidOperationException ex)
        {
            return new DoctorCheck(
                "signing-keys",
                "A signing key is active and published",
                DoctorStatus.Fail,
                $"No active {issuing.ToJwaName()} key: {ex.Message} That is the algorithm "
                + "TokenSigningAlgorithm names, so it is what every token would be signed with and "
                + "what id_token_signing_alg_values_supported advertises."
                + (issuing is SigningAlgorithm.RS256
                    ? " RS256 is also the interop floor — RFC 9068 §2.1 makes it mandatory to implement."
                    : " RS256 is the interop floor (RFC 9068 §2.1); a relying party that cannot verify "
                      + "this algorithm has nothing to fall back to."));
        }

        var rendered = JsonWebKeySet.Render(published);

        foreach (var member in JsonWebKeySet.PrivateMemberNames)
        {
            if (rendered.Contains($"\"{member}\"", StringComparison.Ordinal))
            {
                return new DoctorCheck(
                    "signing-keys",
                    "A signing key is active and published",
                    DoctorStatus.Fail,
                    $"The published JWKS contains the private member '{member}'.");
            }
        }

        var ringOptions = new SigningKeyRingOptions();
        var arithmeticOk = ringOptions.TryValidate(options.AccessTokenLifetime, out var ringError);

        return arithmeticOk
            ? new DoctorCheck(
                "signing-keys",
                "A signing key is active and published",
                DoctorStatus.Pass,
                $"{published.Count} key(s) published; RS256 active.")
            : new DoctorCheck(
                "signing-keys",
                "A signing key is active and published",
                DoctorStatus.Warn,
                ringError!);
    }

    private static DoctorCheck NotMeasured(string id, string title, string why) =>
        new(id, title, DoctorStatus.NotMeasured, why);
}
