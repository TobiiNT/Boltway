using Boltway.AuthorizationServer.Abstractions.Clients;

namespace Boltway.AuthorizationServer.Abstractions.Federation;

/// <summary>
/// Whether a login method is offered, and if not, why not.
/// </summary>
/// <remarks>
/// A-11. There is deliberately no return value meaning "hide me": a configured method that silently
/// vanishes is indistinguishable from one that was never configured, and the support call that
/// follows starts from "the button isn't there" rather than from a sentence naming the cause.
/// </remarks>
public readonly record struct ProviderAvailability
{
    private ProviderAvailability(bool enabled, string? disabledReason)
    {
        Enabled = enabled;
        DisabledReason = disabledReason;
    }

    /// <summary>Whether the control is usable.</summary>
    public bool Enabled { get; }

    /// <summary>
    /// Why it is not, rendered next to the disabled control. <see langword="null"/> iff
    /// <see cref="Enabled"/>.
    /// </summary>
    /// <remarks>
    /// This string reaches an end user's screen. It is plain text and the renderer encodes it, like
    /// every other string on a view model here - but it is written by whoever implemented the
    /// provider, so it should say what a person can act on and nothing about the deployment's
    /// internals.
    /// </remarks>
    public string? DisabledReason { get; }

    /// <summary>The method is offered.</summary>
    public static ProviderAvailability Available => new(true, null);

    /// <summary>
    /// The method is configured and not usable right now. A-11: the reason is required.
    /// </summary>
    /// <param name="reason">What to tell the user. Must not be empty.</param>
    /// <exception cref="ArgumentException"><paramref name="reason"/> is null or blank.</exception>
    public static ProviderAvailability Disabled(string reason)
    {
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new ArgumentException(
                "A disabled login method must state why. A-11 exists because a method that "
                + "disappears without explanation is indistinguishable from one nobody configured.",
                nameof(reason));
        }

        return new(false, reason);
    }
}

/// <summary>What the server knows about the request the login page is standing in the middle of.</summary>
/// <param name="Client">
/// The client whose authorization request sent the user here, or <see langword="null"/> when it
/// could not be resolved.
/// </param>
/// <remarks>
/// <para>
/// <b>The nullable client is the honest part of this type.</b> A-11's acceptance criterion is
/// per-client - "disable a connection for a client ⇒ the login page states why" - so an availability
/// decision that could not see the client would not satisfy it. The login page therefore resolves
/// the client named in its <c>returnUrl</c> before asking. That resolution can fail for reasons that
/// have nothing to do with this decision: the client's metadata document may be unreachable, or the
/// outbound budget may be spent. When it does, this is <see langword="null"/> and a provider that
/// restricts by client has to decide what to do with "I do not know who is asking" - which is a
/// question it should answer deliberately rather than one this type should answer for it by
/// inventing a client record.
/// </para>
/// <para>
/// <b>This differs from the signature in <c>docs/DESIGN.md</c> §3</b>, which declared
/// <c>GetAvailabilityAsync(ClientRecord client, …)</c> with a non-nullable client. That signature
/// cannot be implemented on the login page as it exists, because the page renders before the
/// authorization pipeline has run and the client may not resolve at all. A record type also leaves
/// room to add what the page learns later - the requested scopes, the resources - without changing
/// every implementation.
/// </para>
/// </remarks>
public sealed record ExternalProviderContext(ClientRecord? Client);

/// <summary>
/// Where to send the browser to start an upstream sign-in.
/// </summary>
/// <remarks>
/// The authorization server emits this as the <c>Location</c> of a <c>303</c>, so it is the one
/// value in this file that decides where a user's browser goes next. It is validated on
/// construction rather than at the endpoint: an absolute <c>https</c> URL with no fragment. That is
/// not an open-redirect guard - the value comes from registered code and not from a request - it is
/// a guard against a provider composing a relative or <c>javascript:</c> URL by accident, which
/// would be a redirect to this server's own origin or worse.
/// </remarks>
public sealed record ExternalChallenge
{
    private ExternalChallenge(string location) => Location = location;

    /// <summary>The upstream authorization URL, with every parameter already on it.</summary>
    public string Location { get; }

    /// <summary>The only factory.</summary>
    /// <param name="location">An absolute <c>https</c> URL with no fragment.</param>
    /// <exception cref="ArgumentException">It is not one.</exception>
    public static ExternalChallenge To(string location)
    {
        if (!Uri.TryCreate(location, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException(
                "An external challenge must be an absolute https URL with no fragment.", nameof(location));
        }

        return new ExternalChallenge(location);
    }
}

/// <summary>Everything a provider needs to compose its authorization request.</summary>
/// <param name="CallbackUrl">
/// The absolute redirect URI this server will be at when the upstream sends the browser back.
/// Computed from the configured issuer, never from the request's host - N-13.
/// </param>
/// <param name="State">An opaque CSPRNG value the server has bound to this browser.</param>
/// <param name="Nonce">An opaque CSPRNG value the server will compare against the ID token's claim.</param>
/// <param name="CodeChallenge">The S256 challenge for the verifier the server is holding.</param>
/// <remarks>
/// <para>
/// <b>The server mints <paramref name="State"/>, <paramref name="Nonce"/> and the PKCE verifier, not
/// the provider.</b> Three values whose only job is to be unguessable, generated in one place with
/// <c>RandomNumberGenerator</c>, is a property that holds for every provider ever added; three
/// values each provider generates for itself is a property that holds until someone reaches for
/// <c>Guid.NewGuid</c>. The provider's job is to put them on the URL.
/// </para>
/// <para>
/// The challenge is always S256. There is no parameter for the method, because this server enforces
/// S256 on its own clients (N-02) and an upstream leg that quietly used <c>plain</c> would be the
/// same downgrade one layer up. An upstream that does not support PKCE at all is handled by the
/// provider omitting the parameter, which is a decision it has to make and record.
/// </para>
/// </remarks>
public sealed record ExternalLoginContext(
    string CallbackUrl,
    string State,
    string Nonce,
    string CodeChallenge);

/// <summary>What came back from the upstream, and what is needed to finish.</summary>
/// <param name="Code">The upstream authorization code.</param>
/// <param name="CallbackUrl">The same redirect URI that was sent at the start, byte for byte.</param>
/// <param name="CodeVerifier">The verifier whose challenge was sent at the start.</param>
/// <param name="Parameters">
/// Every query parameter the upstream sent, so a provider can check the RFC 9207 <c>iss</c>.
/// </param>
/// <remarks>
/// <c>state</c> is absent from what a provider is asked to do, deliberately. It is compared against
/// the browser's pending-request cookie by the server before this type is ever built, so a provider
/// cannot forget to compare it and cannot compare it wrongly.
/// </remarks>
public sealed record ExternalCallbackContext(
    string Code,
    string CallbackUrl,
    string CodeVerifier,
    IReadOnlyDictionary<string, string> Parameters);

/// <summary>
/// An identity as an upstream asserts it.
/// </summary>
/// <param name="Issuer">
/// The upstream issuer identifier - the <c>iss</c> of the ID token, which the provider has already
/// checked against its configuration.
/// </param>
/// <param name="Subject">The subject as that provider knows it. Never used as this server's <c>sub</c>.</param>
/// <param name="Nonce">
/// The <c>nonce</c> claim exactly as it appeared in the signed token, or <see langword="null"/> if
/// there was none. <b>Uncompared.</b>
/// </param>
/// <param name="Claims">
/// Everything else the provider chose to surface, as strings. Read for display and for provisioning;
/// never for deciding which local account this is.
/// </param>
/// <remarks>
/// <para>
/// D-10: the local <c>sub</c> is a ULID minted by this server and joined to
/// <paramref name="Issuer"/> and <paramref name="Subject"/> through the <c>ExternalLogin</c> table.
/// An upstream subject is never passed through into a token.
/// </para>
/// <para>
/// <paramref name="Nonce"/> is returned rather than checked because the value it must equal lives in
/// the browser's pending-request cookie, which is the server's to read and not the provider's. The
/// comparison happens in one place for every provider, and it is a constant-time one.
/// </para>
/// </remarks>
public sealed record ExternalPrincipal(
    string Issuer,
    string Subject,
    string? Nonce,
    IReadOnlyDictionary<string, string> Claims);

/// <summary>Why an upstream leg did not produce a principal.</summary>
/// <remarks>
/// A closed set owned by this assembly rather than the <c>ReasonCode</c> enum, so a provider chooses
/// from the causes it can actually distinguish and the server keeps ownership of what gets logged
/// and under which requirement id. Every member below maps to exactly one <c>ReasonCode</c>.
/// </remarks>
public enum ExternalFailureKind
{
    /// <summary>Unset. Never returned; present so <c>default</c> is not a real failure.</summary>
    None = 0,

    /// <summary>The token endpoint could not be reached, refused, or answered something unusable.</summary>
    TokenExchangeFailed,

    /// <summary>The exchange succeeded and there was no ID token in it.</summary>
    IdentityTokenMissing,

    /// <summary>
    /// The ID token did not validate: signature, <c>alg</c>, <c>iss</c>, <c>aud</c>, <c>exp</c>,
    /// <c>iat</c>, or it carried no <c>sub</c>.
    /// </summary>
    /// <remarks>
    /// One member for all of them, matching how <c>AccessTokenRejected</c> works on the resource
    /// server: which check failed goes in the detail, for the log, and never to the user - the
    /// difference between "wrong key" and "wrong issuer" is a fact about this server's configuration
    /// and about whoever is impersonating the upstream.
    /// </remarks>
    IdentityTokenRejected,

    /// <summary>The provider cannot run: no signing keys, no endpoints, missing credential.</summary>
    ProviderUnavailable,
}

/// <summary>The outcome of an upstream round trip.</summary>
public abstract record ExternalLoginResult
{
    private ExternalLoginResult() { }

    /// <summary>The upstream asserted an identity and every check the provider makes passed.</summary>
    public sealed record Authenticated(ExternalPrincipal Principal) : ExternalLoginResult;

    /// <summary>The provider refused. <paramref name="Detail"/> is for the log, never the user.</summary>
    public sealed record Failed(ExternalFailureKind Kind, string Detail) : ExternalLoginResult;
}

/// <summary>
/// One upstream identity provider.
/// </summary>
/// <remarks>
/// <para>
/// The seam D-10 asks for, and the shape that makes "Google is not special" true: everything
/// specific to Google in the shipped implementation is four configured URLs, a scheme name and a
/// display name. Facebook, Entra or an enterprise OIDC deployment is the same generic provider with
/// different configuration.
/// </para>
/// <para>
/// <b>What an implementer must do, and what the server does for them.</b> The server mints the
/// <c>state</c>, the <c>nonce</c> and the PKCE verifier; binds the <c>state</c> to the browser and
/// compares it on the way back; compares the <c>nonce</c> against the signed claim; and decides
/// which local account the result maps to. An implementer composes the authorization URL, exchanges
/// the code, and <b>validates the ID token</b> - signature, algorithm, issuer, audience and
/// lifetime. That last one cannot be moved into the server without the server knowing how to fetch
/// and cache one provider's keys, which is exactly the thing that differs between providers.
/// </para>
/// <para>
/// Nothing here takes an <c>HttpContext</c>, so an implementation is unit-testable in a class
/// library. That is this assembly's rule and it is worth restating for a seam this security-relevant:
/// a provider that could read the request could read the pending-request cookie.
/// </para>
/// </remarks>
public interface IExternalIdentityProvider
{
    /// <summary>
    /// The route segment this provider is reached at: <c>/external/{scheme}/start</c>.
    /// </summary>
    /// <remarks>
    /// Must be a short lower-case token of <c>[a-z0-9-]</c>. The server validates it at startup, so a
    /// scheme that would need escaping in a path never reaches a route - A-18's rule applied to a
    /// value that becomes part of a URL.
    /// </remarks>
    string Scheme { get; }

    /// <summary>What the button says. Plain text; the renderer encodes it.</summary>
    string DisplayName { get; }

    /// <summary>
    /// The <c>iss</c> this provider's tokens carry - how a stored link is recognised as this one.
    /// </summary>
    /// <remarks>
    /// A link is stored as <c>(issuer, upstream subject)</c> and never as a scheme, because a
    /// scheme is this server's routing name and could be renamed under a directory that would then
    /// silently stop matching. So a page listing providers beside what an account already holds has
    /// to join the two on something the token asserts, and this is it.
    /// </remarks>
    string Issuer { get; }

    /// <summary>Whether this method is usable for this request, and if not, why not.</summary>
    ValueTask<ProviderAvailability> GetAvailabilityAsync(
        ExternalProviderContext context, CancellationToken cancellationToken);

    /// <summary>
    /// The origin a challenge will navigate the browser to, for <c>form-action</c>.
    /// </summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>
    /// An origin - scheme, host and port, no path - or <see langword="null"/> when it cannot be
    /// determined right now, in which case no button for this provider will work and the page says
    /// nothing about why.
    /// </returns>
    /// <remarks>
    /// <para>
    /// <b>Why a provider has to answer this before anyone clicks anything.</b> A provider button is
    /// a form that posts here and is answered with a redirect to the upstream - and Chrome and
    /// Safari apply <c>form-action</c> to the redirect a submission follows, not only to its
    /// immediate target. Under the shipped <c>form-action 'self'</c> the browser blocks that
    /// navigation and reports nothing to the server: the page simply does not move. Measured on a
    /// running deployment, by pressing "Link Google" and watching nothing happen. Every
    /// <c>curl</c> check of the same flow passed, because <c>curl</c> does not enforce CSP.
    /// </para>
    /// <para>
    /// A policy is a response header, so it is decided when the page is built rather than when the
    /// button is pressed. That is the whole reason this is a member here and not something the
    /// start endpoint could work out for itself - by then the header has shipped.
    /// </para>
    /// <para>
    /// <b>Not defaulted, deliberately.</b> A default returning <see langword="null"/> would compile
    /// against every existing implementation and hand each of them a button that silently does
    /// nothing, which is the defect this exists to close. An implementer who has to write a line
    /// here is an implementer who has been told.
    /// </para>
    /// </remarks>
    ValueTask<string?> GetChallengeOriginAsync(CancellationToken cancellationToken);

    /// <summary>Compose the upstream authorization request.</summary>
    ValueTask<ExternalChallenge> BeginAsync(ExternalLoginContext context, CancellationToken cancellationToken);

    /// <summary>Exchange the code and validate what comes back.</summary>
    ValueTask<ExternalLoginResult> CompleteAsync(
        ExternalCallbackContext context, CancellationToken cancellationToken);
}
