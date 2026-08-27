using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Http;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Redirects;

namespace Boltway.AuthorizationServer.Clients;

/// <summary>
/// Turns the bytes of a Client ID Metadata Document into a <see cref="ClientRecord"/>, or says why
/// not. CIMD §4.
/// </summary>
/// <remarks>
/// <para>
/// Every refusal returns its own sentence. That is X-03's whole content: the CIMD failure conditions
/// it enumerates each have to be distinguishable from the outside, because the only tools available
/// to whoever is debugging a failed connection are <c>curl</c> and the error body (A-12). Its row
/// lists ten of them, separated by slashes, and one of those (<c>client_secret*</c>) is a glob over
/// two member names.
/// </para>
/// <para>
/// <b>Shape is strict, content is not.</b> A member that is present with the wrong JSON type is a
/// malformed document and is refused. A member whose <i>value</i> this server does not use - an
/// unfamiliar entry in <c>grant_types</c>, say - is carried through untouched, because C-14: a
/// client declaring a grant this server has not enabled is not an error, it is a client that also
/// works elsewhere. The request is where that gets checked, against this record.
/// </para>
/// </remarks>
internal static class CimdDocument
{
    /// <summary>How much of a caller-supplied value may appear in an error description.</summary>
    /// <remarks>
    /// <c>ErrorText.Safe</c> filters the characters and caps the whole description at 240, which
    /// means an unbounded echo would push the sentence that explains the failure off the end. This
    /// keeps the explanation and truncates the evidence instead.
    /// </remarks>
    private const int MaxEcho = 40;

    /// <summary>
    /// The three named symmetric methods of §4.1.
    /// </summary>
    /// <remarks>
    /// §4.1 also bans "any other method based around a shared symmetric secret". That half is
    /// covered by the closed allowlist at the end of <c>TryReadAuthMethod</c> rather than by adding
    /// guesses to this list: anything not <c>none</c> and not <c>private_key_jwt</c> is refused, so
    /// a symmetric method invented after this was written cannot pass by not being enumerated here.
    /// This list exists only so those three get the more specific message.
    /// </remarks>
    private static readonly string[] SymmetricAuthMethods =
    [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
    ];

    /// <summary>
    /// JWK members that carry a private or symmetric key. RFC 7518 §6.
    /// </summary>
    /// <remarks>
    /// <c>d</c> is the RSA private exponent and also the EC and OKP private key; <c>p</c>, <c>q</c>,
    /// <c>dp</c>, <c>dq</c> and <c>qi</c> are the RSA CRT parameters; <c>k</c> is the octet sequence
    /// of a symmetric key. §4.1: "private key material MUST NOT be included in the Client ID
    /// Metadata Document; only public keys ... are permitted".
    /// </remarks>
    private static readonly string[] PrivateJwkMembers = ["d", "p", "q", "dp", "dq", "qi", "k"];

    /// <summary>Read and validate, or explain which check refused it.</summary>
    internal static bool TryRead(
        byte[] body,
        MediaType contentType,
        CimdClientIdUrl clientId,
        CimdClientResolverOptions options,
        [NotNullWhen(true)] out ClientRecord? client,
        [NotNullWhen(false)] out string? failure)
    {
        client = null;

        // §4: "the response is JSON and conforms to application/<AS-defined>+json". Parsed through
        // MediaType rather than compared as a string, because the two vendors do not agree on the
        // spelling - claude.ai serves `application/json` and chatgpt.com serves
        // `application/json; charset=utf-8`, and an equality test accepts one and refuses the other.
        //
        // The cost of enforcing this at all is that a document served as text/plain is refused, and
        // no measurement says one exists. The benefit is that a JSON file a site serves as an
        // uploaded attachment is not automatically a client identity on that site's origin.
        if (!contentType.IsJson)
        {
            failure = $"The client metadata document was served as '{Echo(contentType.ToString())}', not JSON (CIMD section 4).";
            return false;
        }

        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(body);
        }
        catch (JsonException)
        {
            failure = "The client metadata document is not valid JSON (CIMD section 4).";
            return false;
        }

        using (document)
        {
            return TryReadRoot(document.RootElement, clientId, options, out client, out failure);
        }
    }

    private static bool TryReadRoot(
        JsonElement root,
        CimdClientIdUrl clientId,
        CimdClientResolverOptions options,
        [NotNullWhen(true)] out ClientRecord? client,
        [NotNullWhen(false)] out string? failure)
    {
        client = null;

        if (root.ValueKind is not JsonValueKind.Object)
        {
            failure = "The client metadata document is not a JSON object (CIMD section 4).";
            return false;
        }

        // ───────── §4: the document names itself, and that IS the security model ─────────
        //
        // Without this check, anyone who can host a JSON file can publish a document claiming any
        // client_id, and the URL in the authorization request stops meaning anything. §4 requires
        // the match against "the URL that the authorization server used to fetch the document", and
        // requires simple string comparison - so this is ordinal on the raw strings, and
        // https://example.com/c does not match https://example.com:443/c.
        //
        // It is also what closes the percent-encoding gap the §3 checks do not cover. Measured:
        // https://example.com/%63allback is fetched as https://example.com/callback, so the document
        // that answers declares client_id `https://example.com/callback` - which is not the string
        // that was requested, and this comparison refuses it.
        if (!root.TryGetProperty("client_id", out var declared) || declared.ValueKind is not JsonValueKind.String)
        {
            failure = "The client metadata document has no string 'client_id' member (CIMD section 4).";
            return false;
        }

        if (!string.Equals(declared.GetString(), clientId.Value, StringComparison.Ordinal))
        {
            failure = "The client metadata document's 'client_id' is not the URL it was fetched from (CIMD section 4).";
            return false;
        }

        // ───────── §4.1: credential and key material restrictions ─────────

        if (root.TryGetProperty("client_secret", out _))
        {
            failure = "A client metadata document must not carry 'client_secret' (CIMD section 4.1).";
            return false;
        }

        if (root.TryGetProperty("client_secret_expires_at", out _))
        {
            failure = "A client metadata document must not carry 'client_secret_expires_at' (CIMD section 4.1).";
            return false;
        }

        if (!TryReadAuthMethod(root, out var method, out failure))
        {
            return false;
        }

        var hasJwks = root.TryGetProperty("jwks", out var jwks);
        var hasJwksUri = root.TryGetProperty("jwks_uri", out var jwksUriElement);

        // RFC 7591 §2: the two are mutually exclusive. With both, which one authenticates the client
        // is a question the document does not answer, and the answer decides who may spend its
        // grants.
        if (hasJwks && hasJwksUri)
        {
            failure = "A client metadata document must not carry both 'jwks' and 'jwks_uri' (RFC 7591 section 2).";
            return false;
        }

        if (hasJwks && !TryCheckJwks(jwks, out failure))
        {
            return false;
        }

        string? jwksUri = null;

        if (hasJwksUri)
        {
            // §8.6: only fetch or parse URLs with known and supported schemes. This value is
            // dereferenced later, by the same guarded fetcher, so an unusable one is caught here
            // rather than at the first token request.
            if (jwksUriElement.ValueKind is not JsonValueKind.String
                || !AbsoluteHttpsUrl.TryCreate(jwksUriElement.GetString(), out _))
            {
                failure = "The client metadata document's 'jwks_uri' is not an absolute https URL (CIMD section 8.6).";
                return false;
            }

            jwksUri = jwksUriElement.GetString();
        }

        // §8.2: a client declaring private_key_jwt MUST be authenticated with the key discovered
        // from its metadata document. ClientRecord carries a jwks_uri and has nowhere to put an
        // inline key set, so a document that declares the method and publishes its keys inline
        // cannot be authenticated by this server - and saying so is better than registering a
        // confidential client whose first token request fails for a reason nothing explains.
        if (method is ClientAuthMethod.PrivateKeyJwt && jwksUri is null)
        {
            failure = "'private_key_jwt' needs a 'jwks_uri' in the client metadata document (CIMD section 8.2).";
            return false;
        }

        // ───────── §4.2: redirect URL registration ─────────

        if (!TryReadRedirectUris(root, clientId, options, out var redirectUris, out failure))
        {
            return false;
        }

        if (!TryReadStringArray(root, "grant_types", out var grantTypes, out failure)
            || !TryReadStringArray(root, "response_types", out var responseTypes, out failure)
            || !TryReadString(root, "client_name", out var clientName, out failure)
            || !TryReadHttpsUrl(root, "logo_uri", out var logoUri, out failure))
        {
            return false;
        }

        client = new ClientRecord
        {
            // ForCimd, so the record carries how the identifier was obtained. C-01 and §7.1: never
            // re-derive "is this CIMD?" from an https:// prefix, because an administrator may issue
            // URL-shaped identifiers for clients that are not CIMD clients at all.
            ClientId = ClientIdentifier.ForCimd(clientId.Value),

            // §8.2: publishing a public key and declaring private_key_jwt "establishes this client
            // as a confidential client". Everything else here is public - there is no third option,
            // because §4.1 has removed every way to share a symmetric secret.
            ClientType = method is ClientAuthMethod.PrivateKeyJwt ? ClientType.Confidential : ClientType.Public,

            TokenEndpointAuthMethod = method,
            RedirectUris = redirectUris,
            GrantTypes = grantTypes,
            ResponseTypes = responseTypes,
            ClientName = clientName,
            LogoUri = logoUri,
            JwksUri = jwksUri,

            // AllowedScopes is left empty on purpose, which the pipeline reads as "whatever the
            // server permits". RFC 7591's `scope` member is the client's own statement of what it
            // intends to ask for, and CIMD gives it no more authority than that; turning it into a
            // ceiling would add a refusal path driven by an unauthenticated document. None of the
            // four documents captured on 2026-08-03 carries the member.
        };

        failure = null;
        return true;
    }

    /// <summary>
    /// Read the token endpoint authentication method from both of the spellings that occur in the
    /// field, together, and choose one this server can complete.
    /// </summary>
    /// <remarks>
    /// <para>
    /// C-04. RFC 7591 defines <c>token_endpoint_auth_method</c>, a string. ChatGPT's live documents
    /// also publish <c>token_endpoint_auth_methods_supported</c> - the plural array from RFC 8414,
    /// which is a <i>server</i> metadata field. Reading only the correct spelling means every
    /// ChatGPT document falls through to the default.
    /// </para>
    /// <para>
    /// And the default is the other half of C-04. RFC 7591 §2 says an absent
    /// <c>token_endpoint_auth_method</c> means <c>client_secret_basic</c> - which §4.1 forbids
    /// outright, so an authorization server that applies RFC 7591's default literally refuses every
    /// document that omits the field. The default here is <c>none</c>.
    /// </para>
    /// <para>
    /// <b>Both members are read, and the document's offer is their union.</b> This was an
    /// <c>if</c>/<c>else if</c> - the singular short-circuited the plural - which was correct for
    /// every document captured on 2026-08-03, because no document carried both. On 2026-08-17
    /// <c>https://chatgpt.com/oauth/client.json</c> and <c>https://chatgpt.com/oauth/mcp/client.json</c>
    /// were measured carrying <i>both</i>: <c>"token_endpoint_auth_method":"private_key_jwt"</c>
    /// beside <c>"token_endpoint_auth_methods_supported":["none","private_key_jwt"]</c>. The
    /// singular won, the plural - the half of the document offering the method this server actually
    /// implements - was never read, and every ChatGPT connection resolved to a confidential client
    /// whose token request this server then refused with <c>invalid_client</c>. Reading one member
    /// and skipping the other is how a document that offers two methods gets treated as offering
    /// the one we cannot complete.
    /// </para>
    /// <para>
    /// When the offer holds several, <c>none</c> wins if it is there. That is a policy choice and
    /// not a rule from any specification: <see cref="ClientRecord"/> records one method, the token
    /// endpoint requires the client to use the method it registered, and <c>none</c> is the entry
    /// both vendors offer. Choosing <c>private_key_jwt</c> for a client that also offered
    /// <c>none</c> would require an assertion it may not send - and, today, one this server has no
    /// implementation to verify. The client learns which was chosen the same way it always does:
    /// from <c>token_endpoint_auth_methods_supported</c> in this server's own metadata, which
    /// advertises <c>none</c> and does not advertise <c>private_key_jwt</c>.
    /// </para>
    /// <para>
    /// <b>Measured, where this used to say unverified.</b> The open question was whether ChatGPT
    /// then presents a client assertion anyway - its document declares a preference this choice
    /// overrides, and a client that sends one is refused by <c>ClientAuthentication.Public</c>,
    /// deliberately, since accepting an unverified credential is worse than refusing it. On
    /// 2026-08-17 a live ChatGPT connector linked to a deployment running this code: <c>/token</c>
    /// answered <c>200</c> and no <c>ClientCredentialsUnexpected</c> was raised, so it presented no
    /// assertion and authenticated as a public client. The policy above is therefore what the
    /// client does rather than only what this server prefers.
    /// </para>
    /// </remarks>
    private static bool TryReadAuthMethod(
        JsonElement root, out ClientAuthMethod method, [NotNullWhen(false)] out string? failure)
    {
        method = ClientAuthMethod.None;

        var offered = new List<string>();

        if (root.TryGetProperty("token_endpoint_auth_method", out var singular))
        {
            if (singular.ValueKind is not JsonValueKind.String)
            {
                failure = "'token_endpoint_auth_method' must be a string (RFC 7591 section 2).";
                return false;
            }

            offered.Add(singular.GetString()!);
        }

        if (root.TryGetProperty("token_endpoint_auth_methods_supported", out var plural))
        {
            if (plural.ValueKind is not JsonValueKind.Array)
            {
                failure = "'token_endpoint_auth_methods_supported' must be an array of strings.";
                return false;
            }

            foreach (var element in plural.EnumerateArray())
            {
                if (element.ValueKind is not JsonValueKind.String)
                {
                    failure = "'token_endpoint_auth_methods_supported' must be an array of strings.";
                    return false;
                }

                offered.Add(element.GetString()!);
            }
        }

        // §4.1 says the property "MUST NOT include" the symmetric methods. Include, not equal - so
        // one symmetric entry invalidates the document even when a usable entry sits beside it, and
        // it does so wherever it appears. Running this over the union rather than over whichever
        // member was read first is the second half of the same bug: with the branches, a document
        // spelling `none` in the singular could smuggle `client_secret_basic` through the plural,
        // while the identical plural on its own was refused.
        foreach (var value in offered)
        {
            if (IsSymmetric(value))
            {
                failure = SymmetricRefusal(value);
                return false;
            }
        }

        // Neither member present. RFC 7591's own default is unusable here - see above.
        if (offered.Count is 0)
        {
            failure = null;
            return true;
        }

        if (offered.Contains("none", StringComparer.Ordinal))
        {
            method = ClientAuthMethod.None;
            failure = null;
            return true;
        }

        if (offered.Contains("private_key_jwt", StringComparer.Ordinal))
        {
            method = ClientAuthMethod.PrivateKeyJwt;
            failure = null;
            return true;
        }

        // Nothing in the offer is a method this server knows. The first entry is named because it
        // is the document's own first choice - the singular when there is one, and the head of the
        // array otherwise.
        failure = $"'{Echo(offered[0])}' is not a token endpoint authentication method this server supports.";
        return false;
    }

    private static bool IsSymmetric(string? method) =>
        method is not null && SymmetricAuthMethods.Contains(method, StringComparer.Ordinal);

    private static string SymmetricRefusal(string? method) =>
        $"'{Echo(method)}' needs a shared secret, which a client metadata document cannot establish (CIMD section 4.1).";

    /// <summary>Refuse a JWK set that carries anything but public keys. §4.1.</summary>
    private static bool TryCheckJwks(JsonElement jwks, [NotNullWhen(false)] out string? failure)
    {
        if (jwks.ValueKind is not JsonValueKind.Object
            || !jwks.TryGetProperty("keys", out var keys)
            || keys.ValueKind is not JsonValueKind.Array)
        {
            failure = "The client metadata document's 'jwks' is not a JWK Set (RFC 7517 section 5).";
            return false;
        }

        foreach (var key in keys.EnumerateArray())
        {
            if (key.ValueKind is not JsonValueKind.Object)
            {
                failure = "The client metadata document's 'jwks' is not a JWK Set (RFC 7517 section 5).";
                return false;
            }

            // kty "oct" is a symmetric key: the whole key IS the shared secret §4.1 exists to
            // prevent, and it would be caught by `k` below only if the member were spelled the way
            // RFC 7518 requires.
            if (key.TryGetProperty("kty", out var kty)
                && kty.ValueKind is JsonValueKind.String
                && string.Equals(kty.GetString(), "oct", StringComparison.Ordinal))
            {
                failure = "The client metadata document's 'jwks' contains a symmetric key (CIMD section 4.1).";
                return false;
            }

            foreach (var member in PrivateJwkMembers)
            {
                if (key.TryGetProperty(member, out _))
                {
                    failure = $"The client metadata document's 'jwks' contains private key material ('{member}') (CIMD section 4.1).";
                    return false;
                }
            }
        }

        failure = null;
        return true;
    }

    /// <summary>
    /// Register the document's redirect URIs. §4.2.
    /// </summary>
    /// <remarks>
    /// §4.2: "This method of client information discovery establishes registered redirect URL(s)
    /// when the authorization server fetches the contents of the Client ID Metadata Document." So
    /// this is a registration, and it goes through <see cref="RegisteredRedirectUri.TryRegister"/>
    /// like every other one - the same normalization, the same scheme rules, the same refusal of a
    /// URI carrying a control character. There is deliberately no CIMD-specific redirect parser.
    /// </remarks>
    private static bool TryReadRedirectUris(
        JsonElement root,
        CimdClientIdUrl clientId,
        CimdClientResolverOptions options,
        out IReadOnlyList<RegisteredRedirectUri> result,
        [NotNullWhen(false)] out string? failure)
    {
        result = [];

        if (!root.TryGetProperty("redirect_uris", out var array))
        {
            failure = "The client metadata document has no 'redirect_uris' (CIMD section 4.2).";
            return false;
        }

        if (array.ValueKind is not JsonValueKind.Array)
        {
            failure = "The client metadata document's 'redirect_uris' must be an array of strings (CIMD section 4.2).";
            return false;
        }

        var registered = new List<RegisteredRedirectUri>();

        foreach (var element in array.EnumerateArray())
        {
            if (element.ValueKind is not JsonValueKind.String)
            {
                failure = "The client metadata document's 'redirect_uris' must be an array of strings (CIMD section 4.2).";
                return false;
            }

            if (!RegisteredRedirectUri.TryRegister(element.GetString(), out var uri, out var error))
            {
                // The offending URI is not echoed. It is caller-controlled and up to 2 KB, and
                // naming the rule is what a client needs to fix its document.
                failure = $"A redirect URI in the client metadata document was refused ({error}).";
                return false;
            }

            if (!IsOriginPermitted(uri.Value, clientId, options))
            {
                failure = "An https redirect URI in the client metadata document is not same-origin with the 'client_id' (U-17).";
                return false;
            }

            registered.Add(uri.Value);
        }

        if (registered.Count == 0)
        {
            // §4.2 exempts grant types that use no redirect URL, but this server issues authorization
            // codes and nothing else, so a client with no redirect URI has no flow it could complete.
            failure = "The client metadata document's 'redirect_uris' is empty (CIMD section 4.2).";
            return false;
        }

        result = registered;
        failure = null;
        return true;
    }

    /// <summary>
    /// U-17: an https redirect URI must share the <c>client_id</c>'s origin.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §8.1 leaves this to the authorization server and names what it is for: "the client attempts
    /// to impersonate a more well-known client". Without it, anyone can publish a document at their
    /// own URL declaring <c>client_name: "Claude"</c> and a redirect URI pointing at themselves, and
    /// the consent page's only honest defence - showing the <c>client_id</c> host - is undermined
    /// the moment the code goes somewhere else.
    /// </para>
    /// <para>
    /// The exemptions are not softness, they are the measurement. Claude Code's published document
    /// has <c>client_id</c> on <c>claude.ai</c> and redirect URIs on <c>localhost</c> and
    /// <c>127.0.0.1</c>, so a same-origin rule with no loopback exemption refuses one of the two
    /// clients this server exists to serve. RFC 8252 §7.3 loopback and §7.1 private-use redirects
    /// resolve on the user's own machine and have no web origin to compare against, so the rule is
    /// scoped to <see cref="RedirectKind.Https"/>.
    /// </para>
    /// <para>
    /// Both sides of the comparison go through <see cref="AbsoluteHttpsUrl"/>, so the host is
    /// punycode on both and the port is defaulted on both - which makes
    /// <c>https://claude.ai:443/cb</c> same-origin with <c>https://claude.ai/x</c>. That is correct
    /// for an <i>origin</i> test and is not the identity comparison: §3's simple string comparison
    /// still keeps those two <c>client_id</c> values apart.
    /// </para>
    /// </remarks>
    private static bool IsOriginPermitted(
        RegisteredRedirectUri uri, CimdClientIdUrl clientId, CimdClientResolverOptions options)
    {
        if (uri.Kind is not RedirectKind.Https)
        {
            return true;
        }

        if (!options.RequireSameOriginRedirectUris)
        {
            return true;
        }

        // The escape hatch U-17 asks for. §8.10 and Appendix A make the same point: a strict
        // same-origin rule is hostile to development, so there has to be a way for an operator to
        // name a client_id it has looked at. Per client_id, never per host, so exempting a developer
        // does not exempt everything that host ever publishes.
        if (options.SameOriginExemptClientIds.Contains(clientId.Value))
        {
            return true;
        }

        return AbsoluteHttpsUrl.TryCreate(uri.Value, out var redirect)
            && string.Equals(redirect.Host, clientId.Url.Host, StringComparison.Ordinal)
            && redirect.Port == clientId.Url.Port;
    }

    private static bool TryReadStringArray(
        JsonElement root, string name, out IReadOnlyList<string> result, [NotNullWhen(false)] out string? failure)
    {
        result = [];

        if (!root.TryGetProperty(name, out var array))
        {
            // Absent means "did not say", which C-14 requires be read as permission rather than
            // refusal. The pipeline treats an empty list the same way.
            failure = null;
            return true;
        }

        if (array.ValueKind is not JsonValueKind.Array)
        {
            failure = $"The client metadata document's '{name}' must be an array of strings.";
            return false;
        }

        var values = new List<string>();

        foreach (var element in array.EnumerateArray())
        {
            if (element.ValueKind is not JsonValueKind.String)
            {
                failure = $"The client metadata document's '{name}' must be an array of strings.";
                return false;
            }

            values.Add(element.GetString()!);
        }

        result = values;
        failure = null;
        return true;
    }

    private static bool TryReadString(
        JsonElement root, string name, out string? result, [NotNullWhen(false)] out string? failure)
    {
        result = null;

        if (!root.TryGetProperty(name, out var element))
        {
            failure = null;
            return true;
        }

        if (element.ValueKind is not JsonValueKind.String)
        {
            failure = $"The client metadata document's '{name}' must be a string.";
            return false;
        }

        result = element.GetString();
        failure = null;
        return true;
    }

    /// <summary>Read a member that must be an absolute https URL when it is present at all.</summary>
    /// <remarks>
    /// §8.6 names <c>javascript:</c> in a metadata property as the hazard. The alternative to
    /// refusing was to drop the member and continue, which for <c>logo_uri</c> would be defensible -
    /// a logo is cosmetic. It is refused instead so that every member this class reads follows one
    /// rule, and so that an operator whose document is wrong is told rather than shown a consent page
    /// with a missing image and no explanation. The cost is real: a client whose logo is served over
    /// plain http is refused outright.
    /// </remarks>
    private static bool TryReadHttpsUrl(
        JsonElement root, string name, out string? result, [NotNullWhen(false)] out string? failure)
    {
        if (!TryReadString(root, name, out result, out failure))
        {
            return false;
        }

        if (result is not null && !AbsoluteHttpsUrl.TryCreate(result, out _))
        {
            failure = $"The client metadata document's '{name}' is not an absolute https URL (CIMD section 8.6).";
            return false;
        }

        return true;
    }

    private static string Echo(string? value) =>
        value is null ? "<none>"
        : value.Length <= MaxEcho ? value
        : value[..MaxEcho];
}
