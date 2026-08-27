using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.OAuth.Tokens;

/// <summary>
/// Reads a signing key ring out of a secret, so keys survive a restart.
///
/// <para>
/// The sample generates one at startup and says outright what that costs: every restart
/// invalidates every token the process issued, and a second replica signs with a key the
/// first one's clients have never fetched. On a platform that scales to zero, "restart"
/// means "any quiet ten minutes", so the failure is not rare - it is the normal case, and it
/// surfaces to a user as <c>invalid_token</c> on a session that was working a moment ago.
/// That is a demo ending, and it reads as the client's fault.
/// </para>
///
/// <para>
/// The format keeps the <em>state</em> of each key, not just the material, because
/// <see cref="SigningKeyRing"/> models rotation as three phases and a store that only held
/// "the key" would make rotation impossible without a redeploy. Publish a
/// <see cref="SigningKeyState.Pending"/> key, wait out the cache lead time, promote it to
/// <see cref="SigningKeyState.Active"/> and move the old one to
/// <see cref="SigningKeyState.Retiring"/> - all three steps are edits to one secret.
/// </para>
///
/// <code>
/// [
///   { "kid": "2026-08", "alg": "RS256", "state": "active",
///     "pem": "-----BEGIN PRIVATE KEY-----\n…",
///     "publishedAt": "2026-08-01T00:00:00Z", "activatedAt": "2026-08-01T00:15:00Z" },
///   { "kid": "2026-11", "alg": "RS256", "state": "pending",
///     "pem": "…", "publishedAt": "2026-10-31T00:00:00Z" }
/// ]
/// </code>
/// </summary>
public static class DurableSigningKeys
{
    /// <summary>
    /// Parse a ring from JSON. Throws rather than returning a partial ring: a server that
    /// starts with the wrong keys issues tokens nobody can verify, and every one of those is
    /// a user who has to be told to sign in again.
    /// </summary>
    /// <param name="json">The secret's contents.</param>
    /// <param name="timeProvider">Clock, for defaulting timestamps a secret omits.</param>
    public static IReadOnlyList<ManagedSigningKey> Parse(string json, TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        var now = (timeProvider ?? TimeProvider.System).GetUtcNow();

        List<KeyEntry>? entries;
        try
        {
            entries = JsonSerializer.Deserialize<List<KeyEntry>>(json, Options);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                "The signing key secret is not valid JSON. It is an array of objects, each with at least " +
                "`kid`, `pem` and `state`.", ex);
        }

        if (entries is not { Count: > 0 })
            throw new InvalidOperationException("The signing key secret contains no keys.");

        var keys = new List<ManagedSigningKey>(entries.Count);
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var entry in entries)
        {
            // An unlabelled key is worse than a missing one. The validator runs with
            // TryAllIssuerSigningKeys = false and matches on the token's `kid` header, so a
            // key with no identifier matches nothing and every signature check fails with a
            // message that reads like the key is absent rather than unnamed.
            if (string.IsNullOrWhiteSpace(entry.Kid))
                throw new InvalidOperationException("A signing key has no `kid`. Every key needs one, published in JWKS.");

            if (!seen.Add(entry.Kid))
                throw new InvalidOperationException($"Two signing keys share the `kid` `{entry.Kid}`, so one shadows the other.");

            if (string.IsNullOrWhiteSpace(entry.Pem))
                throw new InvalidOperationException($"Signing key `{entry.Kid}` has no `pem`.");

            var state = ParseState(entry.Kid, entry.State);
            var algorithm = ParseAlgorithm(entry.Kid, entry.Alg);

            keys.Add(new ManagedSigningKey(
                new SigningKeyHandle(entry.Kid, algorithm, Material(entry.Kid, entry.Pem, algorithm)),
                state,
                entry.PublishedAt ?? now,
                entry.ActivatedAt ?? (state is SigningKeyState.Active or SigningKeyState.Retiring ? now : null)));
        }

        // Caught here rather than at the first token request. The ring throws on a missing
        // active key too, but by then the server has started, passed its health check and
        // told the platform it is ready - so the failure arrives as a 500 on a user's sign-in
        // rather than as a deployment that refused to go live.
        if (!keys.Any(k => k.State is SigningKeyState.Active))
        {
            throw new InvalidOperationException(
                "No signing key is `active`, so this server could publish a JWKS and sign nothing. " +
                $"States found: {string.Join(", ", keys.Select(k => $"{k.Handle.Kid}={k.State}".ToLowerInvariant()))}.");
        }

        // Active is not enough: it has to be active for the algorithm the issuer mints with.
        // A ring holding only an ES256 key satisfied the check above, started, published a JWKS
        // full of EC keys, passed its health probe, took traffic - and then answered every token
        // request with an uncaught InvalidOperationException from deep in the minter, three hops
        // from the configuration that caused it. RS256 is the interop floor rather than a
        // preference: RFC 9068 §2.1 makes it mandatory to implement, and OIDC Discovery §3
        // requires it in `id_token_signing_alg_values_supported`.
        if (!keys.Any(k => k.State is SigningKeyState.Active && k.Handle.Algorithm is SigningAlgorithm.RS256))
        {
            throw new InvalidOperationException(
                "No active RS256 signing key. This server issues RS256 and nothing else, so a ring " +
                "without one starts, publishes a JWKS and fails every token request. " +
                $"Active keys: {string.Join(", ", keys.Where(k => k.State is SigningKeyState.Active).Select(k => $"{k.Handle.Kid}={k.Handle.Algorithm}".ToLowerInvariant()))}.");
        }

        return keys;
    }

    /// <summary>
    /// A fresh RSA key as one line of the secret, for standing a deployment up the first time
    /// or for starting a rotation. Written here rather than left to a shell recipe, so the
    /// key that ends up in the vault has the size and the labelling this server requires.
    /// </summary>
    /// <param name="kid">Identifier. A date is a good one - it says when it started.</param>
    /// <param name="state">Usually <c>active</c> for the first key, <c>pending</c> for a rotation.</param>
    /// <param name="timeProvider">Clock.</param>
    public static string NewRsaEntry(string kid, SigningKeyState state = SigningKeyState.Active, TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kid);

        using var rsa = RSA.Create(3072);
        var now = (timeProvider ?? TimeProvider.System).GetUtcNow();

        return JsonSerializer.Serialize(new KeyEntry
        {
            Kid = kid,
            Alg = "RS256",
            State = state.ToString().ToLowerInvariant(),
            Pem = rsa.ExportPkcs8PrivateKeyPem(),
            PublishedAt = now,
            ActivatedAt = state is SigningKeyState.Active ? now : null,
        }, Options);
    }

    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private static SigningKeyState ParseState(string kid, string? state) =>
        (state ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "pending" => SigningKeyState.Pending,
            "active" => SigningKeyState.Active,
            "retiring" => SigningKeyState.Retiring,
            // Not accepted, deliberately: a retired key is one that should have been deleted
            // from the secret, and carrying it forward invites promoting it back by mistake.
            _ => throw new InvalidOperationException(
                $"Signing key `{kid}` has state `{state}`. Use `pending`, `active` or `retiring` — " +
                "a retired key is removed from the secret rather than marked."),
        };

    private static SigningAlgorithm ParseAlgorithm(string kid, string? alg) =>
        (alg ?? "RS256").Trim().ToUpperInvariant() switch
        {
            "RS256" => SigningAlgorithm.RS256,
            "ES256" => SigningAlgorithm.ES256,
            _ => throw new InvalidOperationException($"Signing key `{kid}` names algorithm `{alg}`; this server signs RS256 or ES256."),
        };

    private static SecurityKey Material(string kid, string pem, SigningAlgorithm algorithm)
    {
        try
        {
            if (algorithm is SigningAlgorithm.ES256)
            {
                var ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(pem);
                return new ECDsaSecurityKey(ecdsa);
            }

            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return new RsaSecurityKey(rsa);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            // Measured rather than guessed, because the obvious suspicion is wrong: a PEM that
            // lost every newline on the way through an environment variable still parses, and
            // so does one converted to CRLF. What actually fails is a missing
            // `-----BEGIN …-----` line or a body that was truncated - so that is what the
            // message says to look for.
            throw new InvalidOperationException(
                $"Signing key `{kid}` could not be read as a {algorithm} private key. Check the " +
                "`-----BEGIN …-----` and `-----END …-----` lines are present and the body is complete; " +
                "line endings are not the problem, those survive.", ex);
        }
    }

    private sealed class KeyEntry
    {
        public string? Kid { get; set; }
        public string? Alg { get; set; }
        public string? State { get; set; }
        public string? Pem { get; set; }
        public DateTimeOffset? PublishedAt { get; set; }
        public DateTimeOffset? ActivatedAt { get; set; }
    }
}
