using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Boltway.AuthorizationServer.Configuration;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;

namespace Boltway.AuthorizationServer.Interaction;

/// <summary>Why a federated round trip was started.</summary>
public enum ExternalLoginIntent
{
    /// <summary>To sign in. The pending request resumes an authorization request when it finishes.</summary>
    SignIn = 0,

    /// <summary>
    /// To attach an upstream identity to the account that is already signed in.
    /// </summary>
    /// <remarks>
    /// A separate intent rather than a flag on the same one, because the two have different rules on
    /// the way back: a sign-in must <i>not</i> require an existing session, and a link must require
    /// exactly the session it started from. Deriving one from the other at the callback would mean
    /// reading whether a session happens to exist, which is attacker-influenced.
    /// </remarks>
    Link = 1,
}

/// <summary>
/// What the server is holding while the browser is away at the upstream.
/// </summary>
/// <param name="Scheme">Which provider this was started with.</param>
/// <param name="State">The value the upstream must hand back.</param>
/// <param name="Nonce">The value the ID token must carry.</param>
/// <param name="CodeVerifier">The PKCE verifier whose challenge went out.</param>
/// <param name="ReturnUrl">The local URL to resume, re-gated when it is read back.</param>
/// <param name="Intent">Sign in, or link.</param>
/// <param name="LinkSubject">
/// For <see cref="ExternalLoginIntent.Link"/>, the subject that must still be signed in when the
/// browser comes back. <see langword="null"/> otherwise.
/// </param>
/// <param name="ExpiresAt">When this stops being usable.</param>
public sealed record PendingExternalLogin(
    string Scheme,
    string State,
    string Nonce,
    string CodeVerifier,
    string ReturnUrl,
    ExternalLoginIntent Intent,
    string? LinkSubject,
    DateTimeOffset ExpiresAt);

/// <summary>
/// Carries the pending authorization request across the upstream round trip.
/// </summary>
/// <remarks>
/// <para>
/// <b>Everything that decides where the user ends up is in this cookie, and nothing that decides it
/// comes back from the upstream.</b> That sentence is the whole open-redirect argument. The upstream
/// controls exactly three things on the callback — <c>code</c>, <c>state</c> and <c>error</c> — and
/// none of them is a URL. The <c>returnUrl</c> that the browser is finally sent to was written here,
/// by this server, from a value that had already passed <c>LocalUrl.IsLocalPathTo</c> at the start;
/// it is re-gated on the way out anyway, because "it was validated when it was written" is a claim
/// about a past request and the value has been outside this process since.
/// </para>
/// <para>
/// <b>Why a cookie rather than a server-side row.</b> A row would need a store, a schema, a
/// migration across every deployed database, and a cleanup job — for a value that lives ten minutes
/// and is meaningless to anyone but the browser holding it. The cookie is encrypted and
/// authenticated by ASP.NET Core Data Protection, which is the same mechanism protecting the session
/// and antiforgery cookies this server already relies on, so it inherits their key-management story
/// rather than inventing a second one. The cost is stated rather than hidden: a fleet whose
/// instances do not share a data-protection key ring will fail these callbacks, and the failure is
/// <c>ExternalPendingRequestMissing</c> — which is why that reason exists separately from a state
/// mismatch.
/// </para>
/// <para>
/// <b>Single use.</b> The callback deletes the cookie before it does anything else, so a replayed
/// callback URL finds nothing to compare against. That is what makes a captured <c>state</c>
/// worthless on a second use rather than merely unlikely to work.
/// </para>
/// <para>
/// <c>SameSite=Lax</c>, not <c>Strict</c>, and not by preference: the callback arrives as a
/// top-level cross-site navigation from the upstream, and a <c>Strict</c> cookie is not sent on one.
/// This is the same reason the session cookie is <c>Lax</c>. <c>Lax</c> still withholds the cookie
/// from cross-site sub-resource requests and from cross-site POSTs, which is where CSRF lives.
/// </para>
/// </remarks>
public sealed class ExternalLoginStateStore
{
    /// <summary>
    /// The cookie name.
    /// </summary>
    /// <remarks>
    /// The <c>__Host-</c> prefix is enforced by the browser rather than by us: it refuses the cookie
    /// unless it is <c>Secure</c>, has <c>Path=/</c> and carries no <c>Domain</c>. The last of those
    /// is the one that matters — without it a sibling host on the same registrable domain can set a
    /// cookie this server would read.
    /// </remarks>
    public const string CookieName = "__Host-boltway-external";

    /// <summary>The data-protection purpose string. Changing it invalidates every pending request.</summary>
    private const string ProtectionPurpose = "Boltway.AuthorizationServer.ExternalLogin.v1";

    /// <summary>
    /// Bytes of entropy in <c>state</c>, <c>nonce</c> and the PKCE verifier.
    /// </summary>
    /// <remarks>
    /// 256 bits each, from <see cref="RandomNumberGenerator"/>. N-16 bans <c>System.Random</c>
    /// project-wide and an architecture rule backstops it; <c>Guid.NewGuid</c> makes no cryptographic
    /// promise about its 122 bits and is the thing people reach for here.
    /// </remarks>
    private const int EntropyBytes = 32;

    private readonly IDataProtector _protector;
    private readonly TimeProvider _time;
    private readonly ExternalLoginOptions _options;

    /// <summary>Construct.</summary>
    /// <param name="provider">The host's data-protection provider.</param>
    /// <param name="time">The clock the expiry is checked against.</param>
    /// <param name="options">Federated sign-in configuration.</param>
    public ExternalLoginStateStore(
        IDataProtectionProvider provider, TimeProvider time, ExternalLoginOptions options)
    {
        ArgumentNullException.ThrowIfNull(provider);

        _protector = provider.CreateProtector(ProtectionPurpose);
        _time = time;
        _options = options;
    }

    /// <summary>Mint the three unguessable values and a pending request holding them.</summary>
    /// <param name="scheme">The provider being started.</param>
    /// <param name="returnUrl">The already-gated local URL to resume.</param>
    /// <param name="intent">Sign in, or link.</param>
    /// <param name="linkSubject">The subject a link must still be signed in as.</param>
    public PendingExternalLogin Create(
        string scheme, string returnUrl, ExternalLoginIntent intent, string? linkSubject) =>
        new(
            scheme,
            Unguessable(),
            Unguessable(),
            Unguessable(),
            returnUrl,
            intent,
            linkSubject,
            _time.GetUtcNow() + _options.PendingRequestLifetime);

    /// <summary>Write the pending request to the response as a cookie.</summary>
    public void Write(HttpContext http, PendingExternalLogin pending)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(pending);

        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new PendingPayload
            {
                Scheme = pending.Scheme,
                State = pending.State,
                Nonce = pending.Nonce,
                Verifier = pending.CodeVerifier,
                ReturnUrl = pending.ReturnUrl,
                Intent = (int)pending.Intent,
                LinkSubject = pending.LinkSubject,
                ExpiresAt = pending.ExpiresAt.ToUnixTimeSeconds(),
            },
            PendingPayloadContext.Default.PendingPayload);

        http.Response.Cookies.Append(
            CookieName,
            Convert.ToBase64String(_protector.Protect(payload)),
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Path = "/",
                IsEssential = true,

                // A session cookie, with no Expires. The payload carries its own absolute expiry and
                // that is the one enforced — a cookie lifetime is a hint the browser may round, and
                // this server must not accept a pending request it considers expired just because a
                // browser still had it.
            });
    }

    /// <summary>
    /// Read the pending request and delete the cookie in the same call.
    /// </summary>
    /// <remarks>
    /// Deliberately one method. Reading without deleting is what makes a callback replayable, and a
    /// separate <c>Clear</c> is a call site that can be forgotten on the path that returns early —
    /// which is every failure path, which is where a replay would be aimed.
    /// </remarks>
    /// <returns>The pending request, or <see langword="null"/> if there is not a usable one.</returns>
    public PendingExternalLogin? TakeAndClear(HttpContext http)
    {
        ArgumentNullException.ThrowIfNull(http);

        var cookie = http.Request.Cookies[CookieName];

        // Deleted whatever happens, including when it did not parse. A cookie this server cannot
        // read is a cookie it will never be able to read, and leaving it in place means every
        // subsequent attempt from that browser fails the same way.
        http.Response.Cookies.Delete(
            CookieName,
            new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Path = "/" });

        if (string.IsNullOrEmpty(cookie))
        {
            return null;
        }

        byte[] plaintext;

        try
        {
            plaintext = _protector.Unprotect(Convert.FromBase64String(cookie));
        }
        catch (FormatException)
        {
            return null;
        }
        catch (CryptographicException)
        {
            // Tampered, or protected with a key this instance does not have. Both are "there is no
            // pending request here" as far as this endpoint is concerned; the second is a fleet with
            // an unshared key ring, which the reason code says out loud.
            return null;
        }

        PendingPayload? payload;

        try
        {
            payload = JsonSerializer.Deserialize(plaintext, PendingPayloadContext.Default.PendingPayload);
        }
        catch (JsonException)
        {
            return null;
        }

        if (payload is null
            || string.IsNullOrEmpty(payload.Scheme)
            || string.IsNullOrEmpty(payload.State)
            || string.IsNullOrEmpty(payload.Nonce)
            || string.IsNullOrEmpty(payload.Verifier)
            || string.IsNullOrEmpty(payload.ReturnUrl))
        {
            return null;
        }

        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(
            Math.Clamp(payload.ExpiresAt, MinUnixSeconds, MaxUnixSeconds));

        if (_time.GetUtcNow() >= expiresAt)
        {
            return null;
        }

        return new PendingExternalLogin(
            payload.Scheme,
            payload.State,
            payload.Nonce,
            payload.Verifier,
            payload.ReturnUrl,
            payload.Intent is (int)ExternalLoginIntent.Link
                ? ExternalLoginIntent.Link
                : ExternalLoginIntent.SignIn,
            payload.LinkSubject,
            expiresAt);
    }

    /// <summary>
    /// Whether the <c>state</c> the upstream returned is the one this browser was issued.
    /// </summary>
    /// <remarks>
    /// <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>
    /// rather than <c>string.Equals</c>. The comparison is against a value an attacker supplies and
    /// wants to guess, which is the definition of the case where an early-exit comparison leaks. It
    /// is a small leak here — the value is 256 bits of CSPRNG and the network noise is larger than
    /// the signal — and using the constant-time comparison anyway costs one method call and removes
    /// the argument.
    /// </remarks>
    public static bool StateMatches(string expected, string? presented)
    {
        if (string.IsNullOrEmpty(presented))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(presented));
    }

    /// <summary>Whether the ID token's <c>nonce</c> is the one this browser was issued.</summary>
    /// <remarks>
    /// The same comparison, and separately named because it answers a different question: OIDC Core
    /// §3.1.3.7 rule 11 makes this the relying party's obligation, and it is the check that stops an
    /// ID token obtained for one sign-in being replayed into another. A missing <c>nonce</c> fails,
    /// which is the point — a token issued without one cannot be shown to belong to this round trip.
    /// </remarks>
    public static bool NonceMatches(string expected, string? presented) => StateMatches(expected, presented);

    private static string Unguessable() =>
        OAuth.Primitives.Encoding.Base64Url.Encode(RandomNumberGenerator.GetBytes(EntropyBytes));

    /// <summary>The range <see cref="DateTimeOffset.FromUnixTimeSeconds"/> will accept.</summary>
    /// <remarks>
    /// Clamped rather than range-checked, because the value has already been through
    /// authenticated encryption — an out-of-range number here means this server wrote one, not that
    /// somebody supplied one. It is clamped rather than trusted because
    /// <c>FromUnixTimeSeconds</c> throws on the edges, and a throw on this path is a 500 where a
    /// refusal belongs. The same defect was found and fixed on <c>CookieUserSession</c>'s
    /// <c>auth_time</c>.
    /// </remarks>
    private const long MinUnixSeconds = -62135596800;

    /// <inheritdoc cref="MinUnixSeconds" />
    private const long MaxUnixSeconds = 253402300799;

}

/// <summary>The cookie payload, on its way through the data protector.</summary>
/// <remarks>
/// One-letter member names. Not for the bytes — the payload is encrypted and a few dozen of them
/// change nothing — but because this is a serialization contract with itself across a version
/// boundary, and short opaque names discourage anyone reading a decrypted blob and treating it as a
/// documented format. The purpose string carries the version; changing the shape means changing it.
/// </remarks>
internal sealed class PendingPayload
{
    [JsonPropertyName("s")]
    public string Scheme { get; set; } = string.Empty;

    [JsonPropertyName("t")]
    public string State { get; set; } = string.Empty;

    [JsonPropertyName("n")]
    public string Nonce { get; set; } = string.Empty;

    [JsonPropertyName("v")]
    public string Verifier { get; set; } = string.Empty;

    [JsonPropertyName("r")]
    public string ReturnUrl { get; set; } = string.Empty;

    [JsonPropertyName("i")]
    public int Intent { get; set; }

    [JsonPropertyName("l")]
    public string? LinkSubject { get; set; }

    [JsonPropertyName("x")]
    public long ExpiresAt { get; set; }
}

/// <summary>Source-generated serialization for <see cref="PendingPayload"/>.</summary>
[JsonSerializable(typeof(PendingPayload))]
internal sealed partial class PendingPayloadContext : JsonSerializerContext;
