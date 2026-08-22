using Boltway.Federation.Oidc;
using Boltway.OAuth.Net;

namespace Boltway.Federation.Google;

/// <summary>
/// Google, as configuration.
/// </summary>
/// <remarks>
/// <para>
/// <b>This file is the whole of "support Google", and its size is the point.</b> There is no
/// <c>GoogleOidcProvider</c> class implementing <c>IExternalIdentityProvider</c>, because there is
/// nothing for one to do that <c>OidcExternalProvider</c> does not already do generically. What is
/// here is a scheme name, a display name, an issuer, and the two things a deployment has to supply.
/// <c>docs/DESIGN.md</c> §2 anticipated a <c>GoogleOidcProvider</c> over a generic base; the base
/// turned out to need no subclass, and a class that exists only to be named after a vendor would be
/// the "Google is special" this project split exists to prevent.
/// </para>
/// <para>
/// Adding Facebook, Entra or an enterprise OIDC deployment is a file of this shape, or — because
/// discovery fills in the endpoints — three lines of configuration and no file at all.
/// </para>
/// <para>
/// <b>The endpoints are not hard-coded.</b> Only the issuer is, because the issuer is the one value
/// that must never be discovered: it is what the discovery document is checked against, and what an
/// account's <c>ExternalLogin</c> row is keyed on. Google's authorization, token and JWKS URLs are
/// read from <c>https://accounts.google.com/.well-known/openid-configuration</c> at first use, which
/// is also why the three of them being on three different hosts costs nothing here.
/// </para>
/// </remarks>
public static class GoogleFederation
{
    /// <summary>Google's issuer identifier, as it appears in the <c>iss</c> of its ID tokens.</summary>
    /// <remarks>
    /// Not <c>https://www.googleapis.com</c> and not the <c>accounts.google.com</c> spelling without
    /// a scheme. Google historically issued tokens under two <c>iss</c> values, and the one it uses
    /// for the OIDC flow is this. A deployment that needs the other configures it explicitly rather
    /// than having this constant accept both — an issuer comparison that accepts two values is a
    /// comparison that accepts whichever an attacker prefers.
    /// </remarks>
    public const string Issuer = "https://accounts.google.com";

    /// <summary>The default route segment: <c>/external/google/start</c>.</summary>
    public const string Scheme = "google";

    /// <summary>
    /// Build Google's provider options.
    /// </summary>
    /// <param name="clientId">The OAuth client ID from the Google Cloud console.</param>
    /// <param name="clientSecret">
    /// The client secret, or <see langword="null"/>. Google issues one for a web application and it
    /// is required at its token endpoint, so a null here will surface as a rejected exchange.
    /// </param>
    /// <param name="configure">Anything else — extra scopes, <c>hd</c>, a different scheme name.</param>
    /// <returns>Options ready to hand to <c>AddExternalIdentityProvider</c>.</returns>
    public static OidcProviderOptions Options(
        string clientId, string? clientSecret, Action<OidcProviderOptions>? configure = null)
    {
        var options = new OidcProviderOptions
        {
            Scheme = Scheme,
            DisplayName = "Google",
            Issuer = Issuer,
            ClientId = clientId,

            // Google documents the credential in the request body and accepts Basic as well. The
            // body form is the one its own samples use, so it is the one least likely to be the
            // thing that is wrong when a deployment does not work.
            ClientAuthMethod = UpstreamClientAuthMethod.ClientSecretPost,
        };

        options.SetClientSecret(clientSecret);

        // `openid` and nothing else by default. This server identifies a user by
        // (issuer, subject) and never by email, so requesting the `email` scope would be asking
        // Google for a value no decision here is allowed to depend on. A deployment that wants it
        // for display or for provisioning adds it, deliberately.
        configure?.Invoke(options);

        return options;
    }
}
