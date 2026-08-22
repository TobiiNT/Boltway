using System.Text.Json;
using Boltway.OAuth.Net;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.Federation.Oidc;

/// <summary>The three URLs a relying party needs, once they are known.</summary>
internal sealed record UpstreamEndpoints(
    AbsoluteHttpsUrl Authorization, AbsoluteHttpsUrl Token, AbsoluteHttpsUrl Jwks);

/// <summary>What was asked for, or why it could not be had.</summary>
/// <typeparam name="T">The thing.</typeparam>
internal readonly record struct Resolved<T>(T? Value, string? Detail)
    where T : class
{
    internal static Resolved<T> Ok(T value) => new(value, null);

    internal static Resolved<T> Failed(string detail) => new(null, detail);
}

/// <summary>
/// Holds an upstream's endpoints and signing keys, and refetches them on a schedule this server
/// controls rather than on one a caller can drive.
/// </summary>
/// <remarks>
/// <para>
/// Two caches with different rules, because they answer to different pressures.
/// </para>
/// <para>
/// <b>Discovery</b> changes almost never; it is fetched once and held for a day. The check that
/// matters is not freshness but identity: OIDC Discovery §4.3 requires the document's <c>issuer</c>
/// to equal the issuer it was fetched for, and without that comparison a compromised or
/// misconfigured discovery URL can point this server's credentialed token request anywhere.
/// </para>
/// <para>
/// <b>Keys</b> change on the upstream's schedule, which nobody tells us about. So there are two
/// triggers: an expiry, and a token naming a <c>kid</c> the cache has not seen. The second is
/// necessary — an upstream that signs with a key before we have refetched would otherwise fail every
/// sign-in until the hour was up — and it is also attacker-reachable, because a callback carrying
/// any syntactically valid JWT can name a random <c>kid</c>. That is what
/// <see cref="OidcProviderOptions.JwksMinimumRefreshInterval"/> bounds.
/// </para>
/// <para>
/// Single-flight on both, so a burst of sign-ins after a restart makes one outbound request rather
/// than one per request.
/// </para>
/// </remarks>
internal sealed class UpstreamMetadataCache : IDisposable
{
    private readonly OidcProviderOptions _options;
    private readonly IUpstreamEndpointClient _http;
    private readonly TimeProvider _time;

    private readonly SemaphoreSlim _discoveryGate = new(1, 1);
    private readonly SemaphoreSlim _keyGate = new(1, 1);

    private UpstreamEndpoints? _endpoints;
    private DateTimeOffset _endpointsExpireAt;

    private IReadOnlyList<SecurityKey> _keys = [];
    private DateTimeOffset _keysExpireAt;
    private DateTimeOffset _keysFetchedAt = DateTimeOffset.MinValue;

    internal UpstreamMetadataCache(OidcProviderOptions options, IUpstreamEndpointClient http, TimeProvider time)
    {
        _options = options;
        _http = http;
        _time = time;
    }

    /// <summary>The endpoints, from configuration or from discovery.</summary>
    internal async ValueTask<Resolved<UpstreamEndpoints>> GetEndpointsAsync(CancellationToken cancellationToken)
    {
        // Fully configured: no request, ever. A deployment that spelled out all three endpoints has
        // said it does not want this server talking to a discovery URL, and that is a reasonable
        // thing to want in an air-gapped or tightly-egressed network.
        if (_options.ValidatedAuthorizationEndpoint is { } authorize
            && _options.ValidatedTokenEndpoint is { } token
            && _options.ValidatedJwksUri is { } jwks)
        {
            return Resolved<UpstreamEndpoints>.Ok(new UpstreamEndpoints(authorize, token, jwks));
        }

        var now = _time.GetUtcNow();

        if (_endpoints is { } cached && now < _endpointsExpireAt)
        {
            return Resolved<UpstreamEndpoints>.Ok(cached);
        }

        if (_options.ValidatedDiscoveryUri is not { } discovery)
        {
            return Resolved<UpstreamEndpoints>.Failed(
                "no discovery URL and not every endpoint is configured; options validation should "
                + "have refused this at startup");
        }

        await _discoveryGate.WaitAsync(cancellationToken);

        try
        {
            now = _time.GetUtcNow();

            if (_endpoints is { } raced && now < _endpointsExpireAt)
            {
                return Resolved<UpstreamEndpoints>.Ok(raced);
            }

            var outcome = await _http.GetAsync(
                new UpstreamDocumentRequest(discovery, FetchPurpose.UpstreamDiscovery), cancellationToken);

            if (outcome is not FetchOutcome.Ok ok)
            {
                return Resolved<UpstreamEndpoints>.Failed($"discovery fetch: {Describe(outcome)}");
            }

            var parsed = ParseDiscovery(ok.Body);

            if (parsed.Value is null)
            {
                return Resolved<UpstreamEndpoints>.Failed(parsed.Detail!);
            }

            _endpoints = parsed.Value;
            _endpointsExpireAt = now + _options.DiscoveryCacheLifetime;

            return parsed;
        }
        finally
        {
            _discoveryGate.Release();
        }
    }

    /// <summary>
    /// The upstream's signing keys.
    /// </summary>
    /// <param name="refreshBecauseKeyUnknown">
    /// Whether this call follows a validation failure naming a <c>kid</c> the cached set does not
    /// hold. Honoured only if <see cref="OidcProviderOptions.JwksMinimumRefreshInterval"/> has
    /// elapsed since the last fetch.
    /// </param>
    /// <param name="cancellationToken">Cancellation.</param>
    internal async ValueTask<Resolved<IReadOnlyList<SecurityKey>>> GetKeysAsync(
        bool refreshBecauseKeyUnknown, CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();

        var stale = _keys.Count == 0
            || now >= _keysExpireAt
            || (refreshBecauseKeyUnknown && now - _keysFetchedAt >= _options.JwksMinimumRefreshInterval);

        if (!stale)
        {
            return Resolved<IReadOnlyList<SecurityKey>>.Ok(_keys);
        }

        var endpoints = await GetEndpointsAsync(cancellationToken);

        if (endpoints.Value is null)
        {
            return Resolved<IReadOnlyList<SecurityKey>>.Failed(endpoints.Detail!);
        }

        await _keyGate.WaitAsync(cancellationToken);

        try
        {
            now = _time.GetUtcNow();

            // Re-tested inside the gate. Without this, a hundred requests queued on a cold cache
            // each make their own fetch as they are let through one at a time.
            var stillStale = _keys.Count == 0
                || now >= _keysExpireAt
                || (refreshBecauseKeyUnknown && now - _keysFetchedAt >= _options.JwksMinimumRefreshInterval);

            if (!stillStale)
            {
                return Resolved<IReadOnlyList<SecurityKey>>.Ok(_keys);
            }

            var outcome = await _http.GetAsync(
                new UpstreamDocumentRequest(endpoints.Value.Jwks, FetchPurpose.UpstreamJwks), cancellationToken);

            if (outcome is not FetchOutcome.Ok ok)
            {
                // The old keys are kept and returned when there are any. An upstream JWKS that is
                // briefly unreachable should not fail every sign-in for as long as the outage lasts,
                // and the keys already held are still the ones it published.
                return _keys.Count > 0
                    ? Resolved<IReadOnlyList<SecurityKey>>.Ok(_keys)
                    : Resolved<IReadOnlyList<SecurityKey>>.Failed($"jwks fetch: {Describe(outcome)}");
            }

            IReadOnlyList<SecurityKey> keys;

            try
            {
                // GetSigningKeys(), not Keys: it drops anything whose `use` is not signature and
                // anything it cannot turn into a verification key, so a JWKS carrying an encryption
                // key does not put one in the signature allow-list.
                keys = [.. new Microsoft.IdentityModel.Tokens.JsonWebKeySet(
                    System.Text.Encoding.UTF8.GetString(ok.Body)).GetSigningKeys()];
            }
            catch (ArgumentException ex)
            {
                return _keys.Count > 0
                    ? Resolved<IReadOnlyList<SecurityKey>>.Ok(_keys)
                    : Resolved<IReadOnlyList<SecurityKey>>.Failed($"jwks parse: {ex.GetType().Name}");
            }

            if (keys.Count == 0)
            {
                return _keys.Count > 0
                    ? Resolved<IReadOnlyList<SecurityKey>>.Ok(_keys)
                    : Resolved<IReadOnlyList<SecurityKey>>.Failed("jwks document carries no signing keys");
            }

            _keys = keys;
            _keysFetchedAt = now;
            _keysExpireAt = now + _options.JwksCacheLifetime;

            return Resolved<IReadOnlyList<SecurityKey>>.Ok(keys);
        }
        finally
        {
            _keyGate.Release();
        }
    }

    /// <summary>Read the three endpoints out of a discovery document, checking the issuer first.</summary>
    private Resolved<UpstreamEndpoints> ParseDiscovery(byte[] body)
    {
        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(body);
        }
        catch (JsonException)
        {
            return Resolved<UpstreamEndpoints>.Failed("discovery document is not JSON");
        }

        using (document)
        {
            var root = document.RootElement;

            if (root.ValueKind is not JsonValueKind.Object)
            {
                return Resolved<UpstreamEndpoints>.Failed("discovery document is not a JSON object");
            }

            // OIDC Discovery §4.3, and it is checked before anything else in the document is read.
            // Every other member names a URL this server is about to send a request — and in one
            // case a credential — to, so "is this document about the issuer we asked about" has to
            // be settled first.
            var declared = Member(root, "issuer");

            if (!string.Equals(declared, _options.ValidatedIssuer.Value, StringComparison.Ordinal))
            {
                return Resolved<UpstreamEndpoints>.Failed(
                    $"discovery document declares issuer '{Trim(declared)}', configured is "
                    + $"'{_options.ValidatedIssuer.Value}'");
            }

            var authorize = _options.ValidatedAuthorizationEndpoint
                ?? Url(Member(root, "authorization_endpoint"));
            var token = _options.ValidatedTokenEndpoint ?? Url(Member(root, "token_endpoint"));
            var jwks = _options.ValidatedJwksUri ?? Url(Member(root, "jwks_uri"));

            if (authorize is null || token is null || jwks is null)
            {
                return Resolved<UpstreamEndpoints>.Failed(
                    "discovery document is missing, or does not spell as an absolute https URL, one of "
                    + "authorization_endpoint, token_endpoint, jwks_uri");
            }

            return Resolved<UpstreamEndpoints>.Ok(new UpstreamEndpoints(authorize.Value, token.Value, jwks.Value));
        }
    }

    private static string? Member(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.String
            ? value.GetString()
            : null;

    private static AbsoluteHttpsUrl? Url(string? raw) =>
        AbsoluteHttpsUrl.TryCreate(raw, out var url) ? url : null;

    /// <summary>A short, non-secret description of a failed fetch, for the log.</summary>
    /// <remarks>
    /// Nothing here comes from a request body. The one case that carries text from outside is
    /// <see cref="FetchOutcome.TransportFailed"/>, whose detail is a DNS, TCP or TLS message.
    /// </remarks>
    internal static string Describe(FetchOutcome outcome) => outcome switch
    {
        FetchOutcome.Ok => "ok",
        FetchOutcome.Blocked blocked => $"blocked ({blocked.Reason})",
        FetchOutcome.Redirected redirected => $"redirected ({redirected.Status}), not followed",
        FetchOutcome.NotOk notOk => $"status {notOk.Status}",
        FetchOutcome.TooLarge tooLarge => $"body over {tooLarge.BytesRead} bytes",
        FetchOutcome.Timeout timeout => $"timed out after {timeout.Elapsed.TotalMilliseconds:F0} ms",
        FetchOutcome.TransportFailed failed => $"transport: {Trim(failed.Detail)}",
        FetchOutcome.RateLimited limited => $"outbound budget spent, retry after {limited.RetryAfter}",
        _ => "unknown outcome",
    };

    private static string Trim(string? value) =>
        value is null ? "<none>" : value.Length <= 120 ? value : value[..120];

    /// <summary>Release the two single-flight gates.</summary>
    public void Dispose()
    {
        _discoveryGate.Dispose();
        _keyGate.Dispose();
    }
}
