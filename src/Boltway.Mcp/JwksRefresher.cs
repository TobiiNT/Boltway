// Aliased because this package exports a `ProtectedResourceOptions` of its own, and inside
// this namespace an unqualified name binds to that one. Third collision so far between the
// two RFC 9728 implementations in this repository, and the reason to keep only one.
using RsOptions = Boltway.ResourceServer.Configuration.ProtectedResourceOptions;
using System.Text;
using Boltway.OAuth.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.Mcp;

/// <summary>
/// Keeps a resource server's verification keys current from the authorization server's JWKS.
///
/// <para>
/// <c>ProtectedResourceOptions.SigningKeys</c> is a list somebody has to fill, and the
/// sample fills it once at startup and says plainly that a deployment has to do better:
/// without a refresher the server stops accepting tokens the moment a key is rotated, and
/// it does not notice. Every caller then sees a 401 that re-authenticating cannot fix.
/// </para>
///
/// <para>
/// <strong>It publishes a new list; it never edits one that is being read.</strong> The
/// earlier version called <c>Add</c> and <c>Remove</c> on <c>SigningKeys</c> — the very
/// instance the validator hands to <c>Rfc9068ValidationParameters</c> on every call — from
/// this background timer, with nothing synchronising the two. It was careful to add before
/// removing and never to clear, which closes the window where the server trusts nothing, and
/// the comment then called the remainder harmless on the grounds that a reader can only see
/// a superset. A reader enumerating a <c>List&lt;T&gt;</c> during a structural change does
/// not see a superset; it throws, and the symptom is a rejected token that was perfectly
/// good, on the day a key rotates.
/// </para>
///
/// <para>
/// So <c>ProtectedResourceOptions.SigningKeySource</c> is installed once at start-up and each
/// refresh assigns a whole new list to the field behind it. A request sees the old set or the
/// new one; there is no third state, and no lock on the validation path.
/// </para>
///
/// <para>
/// What it does not do: re-fetch on an unrecognised <c>kid</c>. That is the case that makes
/// a rotation invisible instead of merely slow, and closing it needs a hook into validation
/// failure that the resource server does not expose. Until then the exposure is bounded by
/// the interval, and it is written here rather than assumed closed.
/// </para>
/// </summary>
public sealed class JwksRefresher(
    IUpstreamEndpointClient upstream,
    IOptions<RsOptions> options,
    ILogger<JwksRefresher> logger,
    string issuer,
    TimeSpan interval) : BackgroundService
{
    private IReadOnlyList<SecurityKey> _keys = [];
    private bool _sourceInstalled;

    /// <summary>Fetch once before the host serves traffic, then keep them fresh.</summary>
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        // Before the first fetch, so the validator is reading this class's field rather than the
        // options list for the whole life of the process. Installing it after would leave a window
        // in which two sources of truth existed, which is the shape of bug this change removes.
        if (!_sourceInstalled)
        {
            options.Value.SigningKeySource = () => Volatile.Read(ref _keys);
            _sourceInstalled = true;
        }

        // Deliberately fatal. A connector that starts with no keys refuses every request,
        // and refuses it as a 401 — presenting a startup failure as the caller's problem,
        // in the one shape that makes them try again forever. A container that will not
        // start gets restarted and shows up in the logs as what it is.
        await RefreshAsync(cancellationToken);
        await base.StartAsync(cancellationToken);
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(interval);

        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await RefreshAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Keep the keys we have. A failed refresh is not a reason to stop trusting
                // tokens that are still valid, and the next tick may well succeed.
                logger.LogWarning(ex, "Could not refresh signing keys from {Issuer}; keeping the current set.", issuer);
            }
        }
    }

    private async Task RefreshAsync(CancellationToken ct)
    {
        // Through the guarded client rather than a bare HttpClient, and the reason is that this
        // class spent its whole life outside the rule that says so. It lived in a second source
        // tree with its own solution, so Only_the_guarded_fetcher_touches_system_net_http never
        // walked it; folding the trees together turned the ban red on the first run. A raw
        // HttpClient here follows redirects, reads an unbounded body, and applies none of the
        // address checks — against a URL derived from operator configuration, which is the weakest
        // of the reasons to trust it and not one of the strong ones.
        if (!AbsoluteHttpsUrl.TryCreate(issuer.TrimEnd('/') + "/.well-known/jwks.json", out var jwksUrl))
        {
            throw new InvalidOperationException(
                $"The issuer '{issuer}' does not yield an absolute https JWKS URL. A key set reached "
                + "over anything but https is a key set an intermediary can choose.");
        }

        var outcome = await upstream.GetAsync(
            new UpstreamDocumentRequest(jwksUrl, FetchPurpose.AuthorizationServerJwks), ct);

        if (outcome is not FetchOutcome.Ok ok)
        {
            throw new InvalidOperationException(
                $"The JWKS at {issuer} could not be fetched: {outcome.GetType().Name}. The keys "
                + "already held are kept; this is not a rotation.");
        }

        IReadOnlyList<SecurityKey> next =
            [.. new JsonWebKeySet(Encoding.UTF8.GetString(ok.Body)).GetSigningKeys()];
        var previous = Volatile.Read(ref _keys);

        // The third value on this axis, and it used to be folded into the second.
        //
        // A refresh either fails, or succeeds with keys, or succeeds with none — and only the first
        // two were distinguished. `JsonWebKeySet` parses `{"keys":[]}`, `{}`, a proxy's JSON error
        // page and a set holding nothing but encryption keys, all without throwing, and every one
        // of them arrived here as a successful rotation that happened to withdraw everything.
        //
        // Measured: with `{"keys":[]}` at startup the process came up with zero keys and no
        // exception, which is what the "Deliberately fatal" comment on StartAsync says cannot
        // happen — /health kept answering 200 because it is anonymous, so the container was green
        // while every tool call got a 401 that re-authenticating cannot fix. Mid-flight the same
        // body withdrew a working key and said so at Information, the same level as an ordinary
        // rotation.
        //
        // Thrown rather than returned, because the two callers already want opposite things and
        // both already handle a throw: StartAsync lets it out and the container dies as designed,
        // ExecuteAsync catches it, keeps the keys it has, and warns. Thrown *before* the write, so
        // the keeping is real rather than a restore.
        if (next.Count == 0)
        {
            throw new InvalidOperationException(
                $"The JWKS at {issuer} was fetched but holds no usable signing key. This is not a "
                + "rotation: an empty or unparsable key set withdraws every key at once, and every "
                + "caller then sees a 401 that re-authenticating cannot fix.");
        }

        // One reference assignment, so a request either sees the whole old set or the whole new one.
        // Nothing in between exists to be read.
        Volatile.Write(ref _keys, next);

        // The diff exists only to be logged, and it is two O(n²) passes over the key set. Computing
        // it outside the guard meant a refresher on a large key set paid for a sentence nobody was
        // listening to; CA1873 flags the argument, but the argument was never the expensive part.
        if (logger.IsEnabled(LogLevel.Information))
        {
            var added = next.Count(k => !previous.Any(existing => Same(existing, k)));
            var withdrawn = previous.Count(existing => !next.Any(k => Same(existing, k)));

            if (added > 0 || withdrawn > 0)
            {
                logger.LogInformation(
                    "Signing keys from {Issuer}: {Added} added, {Removed} withdrawn, {Total} trusted.",
                    issuer, added, withdrawn, next.Count);
            }
        }
    }

    // The `kid` is the identity: the validator runs with TryAllIssuerSigningKeys = false and
    // matches on the token's kid header, so two keys with the same kid are the same slot.
    private static bool Same(SecurityKey a, SecurityKey b) =>
        string.Equals(a.KeyId, b.KeyId, StringComparison.Ordinal);
}

/// <summary>Wiring the refresher.</summary>
public static class JwksRefresherExtensions
{
    /// <summary>
    /// Fill and keep filling <c>ProtectedResourceOptions.SigningKeys</c> from the
    /// authorization server's JWKS. Call after <c>AddBoltwayProtectedResource</c>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="issuer">The authorization server's issuer URL.</param>
    /// <param name="interval">How often to re-fetch. Defaults to five minutes.</param>
    public static IServiceCollection AddJwksSigningKeys(
        this IServiceCollection services,
        string issuer,
        TimeSpan? interval = null)
    {
        services.AddHostedService(sp => new JwksRefresher(
            sp.GetRequiredService<IUpstreamEndpointClient>(),
            sp.GetRequiredService<IOptions<RsOptions>>(),
            sp.GetRequiredService<ILogger<JwksRefresher>>(),
            issuer,
            interval ?? TimeSpan.FromMinutes(5)));

        return services;
    }
}
