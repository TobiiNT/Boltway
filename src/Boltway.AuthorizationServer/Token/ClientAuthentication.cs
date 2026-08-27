using System.Text;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Requests;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.AuthorizationServer.Token;

/// <summary>What the token endpoint knows before it has decided who the client is.</summary>
/// <param name="Parameters">The form body.</param>
/// <param name="AuthorizationHeader">The raw <c>Authorization</c> header, or <see langword="null"/>.</param>
public sealed record ClientAuthenticationContext(OAuthParameters Parameters, string? AuthorizationHeader);

/// <summary>The outcome of authenticating a client.</summary>
public abstract record ClientAuthentication
{
    private ClientAuthentication() { }

    /// <summary>The client is who it says it is.</summary>
    /// <param name="Client">The resolved client.</param>
    /// <param name="Method">How it authenticated.</param>
    public sealed record Authenticated(ClientRecord Client, ClientAuthMethod Method) : ClientAuthentication
    {
        /// <summary>Whether the credential arrived in the <c>Authorization</c> header.</summary>
        /// <remarks>
        /// Derived from the method rather than stored, so it cannot disagree with it. Carried past
        /// authentication because a failure raised <i>later</i> - an unauthorized grant type, say -
        /// still has to answer §5.2's 401-versus-400 question about how this client authenticated.
        /// </remarks>
        public bool UsedAuthorizationHeader => Method is ClientAuthMethod.ClientSecretBasic;

        /// <summary>
        /// The scheme to echo in <c>WWW-Authenticate</c> on a 401. Always <c>Basic</c>.
        /// </summary>
        /// <remarks>
        /// A constant rather than a function of <see cref="Method"/>, because only one method is
        /// challengeable. <c>client_secret_post</c> and <c>private_key_jwt</c> carry their credential
        /// in the body, which RFC 7235 has no challenge form for, and <c>none</c> carries none at all
        /// - all three answer 400, where <see cref="UsedAuthorizationHeader"/> is false and this
        /// value is never read.
        /// </remarks>
        public static string ChallengeScheme => "Basic";
    }

    /// <summary>It is not.</summary>
    /// <param name="Rejection">
    /// Which check failed, in both the form the client is told and the form the log needs.
    /// </param>
    /// <param name="UsedAuthorizationHeader">
    /// Whether credentials arrived in the <c>Authorization</c> header, which decides 401 vs 400.
    /// </param>
    /// <param name="ChallengeScheme">The scheme to echo in <c>WWW-Authenticate</c> on a 401.</param>
    /// <remarks>
    /// The rejection travels with the failure rather than being rebuilt at the endpoint. Client
    /// authentication is where the response is deliberately least informative - "Client
    /// authentication failed" covers an unknown client, a disabled one, a missing secret and a wrong
    /// one - so this is the type that most needs the two halves kept together.
    /// </remarks>
    public sealed record Failed(
        Rejection Rejection,
        bool UsedAuthorizationHeader,
        string ChallengeScheme = "Basic") : ClientAuthentication
    {
        /// <summary>The OAuth error the client is told.</summary>
        public OAuthErrorCode Code => Rejection.Error;

        /// <summary>Which check failed, in words the client sees.</summary>
        public string Description => Rejection.Description;
    }
}

/// <summary>
/// Authenticates the client at the token endpoint.
/// </summary>
/// <remarks>
/// <para>
/// The order below is not interchangeable. Counting the presented mechanisms happens <b>before</b>
/// any of them is validated, because OAuth 2.1 §2.4 forbids using more than one - "to prevent a
/// conflict of which authentication mechanism is authoritative for the request" - and a server that
/// validates first and counts second has already picked one.
/// </para>
/// <para>
/// The method a client may use is the one it <b>registered</b>, not the one it presents. A client
/// registered <c>none</c> that arrives with a secret is refused rather than upgraded, and a client
/// registered <c>client_secret_basic</c> that arrives with nothing is refused rather than
/// downgraded - the second is the one that matters, because a downgrade is silent and turns a
/// confidential client into a public one.
/// </para>
/// </remarks>
public sealed class ClientAuthenticator(
    IReadOnlyList<IClientResolver> resolvers,
    IClientSecretStore secrets,
    IReadOnlyList<ClientAuthMethod> enabledMethods,
    ClientAssertionAuthenticator? assertions = null)
{
    private readonly IReadOnlyList<IClientResolver> _resolvers = resolvers ?? throw new ArgumentNullException(nameof(resolvers));
    private readonly IClientSecretStore _secrets = secrets ?? throw new ArgumentNullException(nameof(secrets));
    private readonly IReadOnlyList<ClientAuthMethod> _enabled = enabledMethods ?? throw new ArgumentNullException(nameof(enabledMethods));

    /// <summary>
    /// The assertion verifier, or <see langword="null"/> when no deployment asked for one.
    /// </summary>
    /// <remarks>
    /// Optional rather than required, and the arm below turns its absence into
    /// <c>ClientAuthMethodNotImplemented</c> rather than a null reference. That path is not
    /// reachable from configuration - options validation refuses <c>private_key_jwt</c> in
    /// <c>TokenEndpointAuthMethods</c> when nothing is registered to serve it, which is the same
    /// rule <c>KnownGrantTypes</c> applies to grants - so reaching it means a host constructed this
    /// type by hand. Answering rather than throwing keeps that a refused request instead of a 500.
    /// </remarks>
    private readonly ClientAssertionAuthenticator? _assertions = assertions;

    /// <summary>Identify and authenticate the client.</summary>
    public async ValueTask<ClientAuthentication> AuthenticateAsync(
        ClientAuthenticationContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var basic = BasicCredentials.TryRead(context.AuthorizationHeader, out var parsed);
        var hasSecretInBody = context.Parameters.Contains("client_secret");
        var hasAssertion = context.Parameters.Contains("client_assertion");

        // Counted before anything is validated. §2.4.
        var presented = (basic ? 1 : 0) + (hasSecretInBody ? 1 : 0) + (hasAssertion ? 1 : 0);

        if (presented > 1)
        {
            return new ClientAuthentication.Failed(
                Rejection.Of(
                    ReasonCode.ClientAuthenticationMethodsCombined,
                    OAuthErrorCode.InvalidRequest,
                    "More than one client authentication mechanism was used.",
                    $"basic={basic}; client_secret={hasSecretInBody}; client_assertion={hasAssertion}"),
                basic);
        }

        if (context.AuthorizationHeader is not null && !basic)
        {
            // A header we could not parse is a credential the client believes it sent. Treating it
            // as absent would silently fall through to `none`, which is a downgrade the client has
            // no way to notice.
            return new ClientAuthentication.Failed(
                Rejection.Of(
                    ReasonCode.ClientAuthorizationHeaderMalformed,
                    OAuthErrorCode.InvalidClient,
                    "The Authorization header is not a well-formed Basic credential.",
                    // The scheme, never the credential. A header that failed to parse may still be
                    // a real secret badly encoded, and "which scheme did they send" is the whole
                    // diagnosis - a client sending Bearer here is pointed at the wrong endpoint.
                    $"scheme={Scheme(context.AuthorizationHeader)}"),
                UsedAuthorizationHeader: true);
        }

        if (!context.Parameters.TrySingle("client_id", out var bodyClientId))
        {
            return new ClientAuthentication.Failed(
                Rejection.Of(
                    ReasonCode.RepeatedParameter,
                    OAuthErrorCode.InvalidRequest,
                    "The 'client_id' parameter appeared more than once.",
                    "parameter=client_id"),
                basic);
        }

        // §4.1.3 binds an authorization code to "the authenticated confidential client, or if the
        // client is public, the client_id in the request". If the header and the body name different
        // clients, that binding check has two candidate identities and no rule for choosing - so the
        // request is refused rather than resolved by precedence.
        if (basic && bodyClientId is not null
            && !string.Equals(parsed.ClientId, bodyClientId, StringComparison.Ordinal))
        {
            return new ClientAuthentication.Failed(
                Rejection.Of(
                    ReasonCode.ClientIdentifierMismatch,
                    OAuthErrorCode.InvalidRequest,
                    "The 'client_id' in the request body does not match the one in the Authorization header.",
                    $"header={parsed.ClientId}; body={bodyClientId}"),
                UsedAuthorizationHeader: true);
        }

        var rawClientId = basic ? parsed.ClientId : bodyClientId;

        if (!ClientIdentifier.TryParseFromRequest(rawClientId, out var clientId))
        {
            // Missing client_id is invalid_request (a missing required parameter, §3.2.4's first
            // clause), not invalid_client - there is no client to have failed authentication.
            return new ClientAuthentication.Failed(
                Rejection.Of(
                    ReasonCode.ClientIdMalformed,
                    OAuthErrorCode.InvalidRequest,
                    "The 'client_id' parameter is missing or malformed.",
                    rawClientId is null ? "client_id absent" : $"client_id={rawClientId}"),
                basic);
        }

        var client = await ResolveAsync(clientId, cancellationToken);

        if (client is null)
        {
            return new ClientAuthentication.Failed(
                Rejection.Of(
                    ReasonCode.ClientUnknown,
                    OAuthErrorCode.InvalidClient,
                    "No client is registered with that identifier.",
                    $"client_id={clientId.Value}"),
                basic);
        }

        if (!client.IsEnabled)
        {
            return new ClientAuthentication.Failed(
                Rejection.Of(
                    ReasonCode.ClientDisabled,
                    OAuthErrorCode.InvalidClient,
                    "This client is disabled.",
                    $"client_id={clientId.Value}"),
                basic);
        }

        var registered = client.TokenEndpointAuthMethod;

        if (!_enabled.Contains(registered))
        {
            return new ClientAuthentication.Failed(
                Rejection.Of(
                    ReasonCode.ClientAuthMethodNotOffered,
                    OAuthErrorCode.InvalidClient,
                    "This client is registered for an authentication method this server does not offer.",
                    $"client_id={clientId.Value}; registered={registered}; enabled={string.Join(' ', _enabled)}"),
                basic);
        }

        return registered switch
        {
            ClientAuthMethod.None => Public(client, basic, hasSecretInBody, hasAssertion),
            ClientAuthMethod.ClientSecretBasic => await SecretAsync(client, basic, parsed.Secret, usedHeader: true, cancellationToken),
            ClientAuthMethod.ClientSecretPost => await PostSecretAsync(client, context, hasSecretInBody, cancellationToken),

            ClientAuthMethod.PrivateKeyJwt when _assertions is not null =>
                await _assertions.AuthenticateAsync(client, context.Parameters, cancellationToken),

            // Registered but not offered is caught above, so reaching here means the enabled list
            // contains a method with no implementation - a wiring error, not a client error.
            _ => new ClientAuthentication.Failed(
                Rejection.Of(
                    ReasonCode.ClientAuthMethodNotImplemented,
                    OAuthErrorCode.InvalidClient,
                    $"Client authentication method '{registered}' is not implemented by this server.",
                    $"client_id={clientId.Value}; registered={registered}"),
                basic),
        };
    }

    /// <summary>
    /// The scheme token from an <c>Authorization</c> header, and nothing after it.
    /// </summary>
    /// <remarks>
    /// The whole header is a credential and must never reach a log. The first token is not: RFC
    /// 7235 §2.1 makes it a fixed vocabulary word, it is the field that distinguishes "this client
    /// is sending Bearer to the token endpoint" from "this client's base64 is broken", and stopping
    /// at the first space means nothing after the scheme can be recovered from what is written.
    /// </remarks>
    private static string Scheme(string? header)
    {
        if (string.IsNullOrEmpty(header))
        {
            return "absent";
        }

        var space = header.IndexOf(' ', StringComparison.Ordinal);

        // Capped as well as split. A header with no space at all is malformed, and "the token before
        // the first space" is then the entire header - which is the credential. The cap is longer
        // than every registered scheme name and far shorter than any credential.
        const int MaxSchemeLength = 20;

        var end = space < 0 ? header.Length : space;

        return end <= MaxSchemeLength ? header[..end] : header[..MaxSchemeLength] + "~";
    }

    private static ClientAuthentication Public(
        ClientRecord client, bool basic, bool hasSecretInBody, bool hasAssertion)
    {
        // A public client that presents a credential is refused rather than accepted-and-ignored.
        // Accepting it would mean the client believes it is authenticating and the server knows it
        // is not - and the client has no way to discover the disagreement.
        if (basic || hasSecretInBody || hasAssertion)
        {
            return new ClientAuthentication.Failed(
                Rejection.Of(
                    ReasonCode.ClientCredentialsUnexpected,
                    OAuthErrorCode.InvalidClient,
                    "This client is registered as public and must not present credentials.",
                    $"client_id={client.ClientId.Value}; basic={basic}; client_secret={hasSecretInBody}; client_assertion={hasAssertion}"),
                basic);
        }

        return new ClientAuthentication.Authenticated(client, ClientAuthMethod.None);
    }

    private async ValueTask<ClientAuthentication> PostSecretAsync(
        ClientRecord client, ClientAuthenticationContext context, bool hasSecretInBody, CancellationToken cancellationToken)
    {
        if (!hasSecretInBody)
        {
            return new ClientAuthentication.Failed(
                Rejection.Of(
                    ReasonCode.ClientCredentialsMissing,
                    OAuthErrorCode.InvalidClient,
                    "This client must authenticate with a client secret.",
                    $"client_id={client.ClientId.Value}; method=client_secret_post"),
                UsedAuthorizationHeader: false);
        }

        _ = context.Parameters.TrySingle("client_secret", out var secret);

        return await SecretAsync(client, presented: true, secret, usedHeader: false, cancellationToken);
    }

    private async ValueTask<ClientAuthentication> SecretAsync(
        ClientRecord client, bool presented, string? secret, bool usedHeader, CancellationToken cancellationToken)
    {
        if (!presented || string.IsNullOrEmpty(secret))
        {
            return new ClientAuthentication.Failed(
                Rejection.Of(
                    ReasonCode.ClientCredentialsMissing,
                    OAuthErrorCode.InvalidClient,
                    "This client must authenticate with a client secret.",
                    $"client_id={client.ClientId.Value}; used_header={usedHeader}"),
                usedHeader);
        }

        var stored = await _secrets.FindAsync(client.ClientId, cancellationToken);

        if (stored is null || !OpaqueSecret.TryParse(secret, TokenPurpose.ClientSecret, out var presentedSecret))
        {
            // Which of the two it was, for the log only. "No secret is stored for this client" and
            // "the presented value is not shaped like one of our secrets" are one answer on the wire
            // - telling them apart says whether a client id exists - and completely different
            // remedies. The presented value itself is never recorded: it is a credential, whatever
            // it turned out to be.
            return new ClientAuthentication.Failed(
                Rejection.Of(
                    ReasonCode.ClientCredentialsInvalid,
                    OAuthErrorCode.InvalidClient,
                    "Client authentication failed.",
                    stored is null
                        ? $"client_id={client.ClientId.Value}; no secret is stored for this client"
                        : $"client_id={client.ClientId.Value}; the presented secret is not a well-formed client secret"),
                usedHeader);
        }

        // Sha256Hash.Matches is a fixed-time comparison. OpaqueSecret.Equals throws by design, so a
        // plaintext comparison here would not compile rather than merely being slower.
        return stored.Value.Matches(presentedSecret)
            ? new ClientAuthentication.Authenticated(client, usedHeader ? ClientAuthMethod.ClientSecretBasic : ClientAuthMethod.ClientSecretPost)
            : new ClientAuthentication.Failed(
                Rejection.Of(
                    ReasonCode.ClientCredentialsInvalid,
                    OAuthErrorCode.InvalidClient,
                    "Client authentication failed.",
                    $"client_id={client.ClientId.Value}; the presented secret does not match the stored hash"),
                usedHeader);
    }

    private async ValueTask<ClientRecord?> ResolveAsync(ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        foreach (var resolver in _resolvers)
        {
            if (!resolver.CanResolve(clientId))
            {
                continue;
            }

            var resolution = await resolver.ResolveAsync(clientId, cancellationToken);

            if (resolution.Client is { } client)
            {
                return client;
            }

            // Every non-NotFound outcome, X-31's RateLimited included, ends as invalid_client here
            // - X-18's row already covers "unresolvable CIMD client_id", and RFC 6749 §5.2 defines
            // no 429 at this endpoint. That is not a gap papered over: reaching /token means
            // /authorize resolved this client seconds earlier, and a successful resolution is cached
            // for at least 300 s and clears the breaker, so a throttled resolution here needs the
            // cache to have been evicted between the two requests. If that ever stops being true,
            // the fix is a shorter path - not a 429 the token endpoint's clients do not parse.
            if (resolution.Error is not ClientResolutionError.NotFound)
            {
                return null;
            }
        }

        return null;
    }
}

/// <summary>Where a confidential client's secret hash lives.</summary>
/// <remarks>
/// Separate from <see cref="IClientStore"/> because the two have different blast radii. A client
/// record is read on every authorization request and is safe to cache; a secret hash is read only
/// here, and keeping it off the record means a log line or a serialization of
/// <see cref="ClientRecord"/> cannot carry it.
/// </remarks>
public interface IClientSecretStore
{
    /// <summary>The stored hash, or <see langword="null"/> for a client with no secret.</summary>
    Task<Sha256Hash?> FindAsync(ClientIdentifier clientId, CancellationToken cancellationToken);
}

/// <summary>An RFC 7617 Basic credential, decoded the way OAuth 2.1 §2.4.1 specifies.</summary>
internal readonly record struct BasicCredentials(string ClientId, string Secret)
{
    /// <summary>Parse an <c>Authorization</c> header, or report that it is not a usable Basic one.</summary>
    /// <remarks>
    /// <para>
    /// Both halves are form-urldecoded after the base64 decode. §2.4.1: "the client identifier is
    /// encoded using the application/x-www-form-urlencoded encoding algorithm … and the encoded
    /// value is used as the username; the client secret is encoded using the same algorithm and
    /// used as the password." The RFC adds that missing this step "has led to many interoperability
    /// problems in the past" - and a CIMD <c>client_id</c> is a URL full of <c>:</c> and <c>/</c>,
    /// so the encoding is doing real work here rather than covering an edge case.
    /// </para>
    /// <para>
    /// Split on the <b>first</b> colon. A secret may contain one; a client id may not, because the
    /// encoding above escapes it.
    /// </para>
    /// </remarks>
    internal static bool TryRead(string? header, out BasicCredentials credentials)
    {
        credentials = default;

        if (header is null)
        {
            return false;
        }

        const string prefix = "Basic ";

        // The scheme is case-insensitive per RFC 7235 §2.1; the parameter after it is not.
        if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var encoded = header[prefix.Length..].Trim();

        if (encoded.Length == 0 || !Convert.TryFromBase64String(encoded, new byte[encoded.Length], out var written))
        {
            return false;
        }

        var buffer = new byte[written];
        _ = Convert.TryFromBase64String(encoded, buffer, out _);

        string decoded;

        try
        {
            // Strict UTF-8, and what it buys is a correct diagnosis rather than a correct decision.
            //
            // The claim here used to be that substituting U+FFFD "would make two different secrets
            // equal". Measured, it does not: a secret must survive OpaqueSecret.TryParse before
            // anything compares it, U+FFFD is not in the base64url alphabet, so a folded credential
            // fails on shape and the client gets the same invalid_client either way. Relaxing this
            // flag leaves the response byte-identical.
            //
            // What changes is who the log says failed. Strict refuses at the header, where the
            // truth is "this credential never parsed". Permissive invents a client id out of
            // replacement characters and then reports a failed secret comparison against it,
            // pointing whoever reads the log at a client that was never named.
            decoded = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(buffer);
        }
        catch (DecoderFallbackException)
        {
            return false;
        }

        var separator = decoded.IndexOf(':', StringComparison.Ordinal);

        if (separator < 0)
        {
            return false;
        }

        credentials = new BasicCredentials(
            Uri.UnescapeDataString(decoded[..separator].Replace('+', ' ')),
            Uri.UnescapeDataString(decoded[(separator + 1)..].Replace('+', ' ')));

        return true;
    }
}
