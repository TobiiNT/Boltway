using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.OAuth.Tokens;

/// <summary>
/// Where a key is in its life. The order matters: a key only ever moves forward.
/// </summary>
/// <remarks>
/// <para>
/// Three phases rather than two, and the middle one is the whole point. A key that starts signing
/// the moment it is created signs tokens that every verifier rejects, because their cached JWKS
/// does not contain it yet - the outage lasts exactly as long as the caches do, and it looks like a
/// signature problem rather than a timing one.
/// </para>
/// <para>
/// So: publish, wait, then sign. And on the way out, stop signing but stay published until the last
/// token signed with the key has expired.
/// </para>
/// </remarks>
public enum SigningKeyState
{
    /// <summary>Not a real state.</summary>
    Unknown = 0,

    /// <summary>
    /// In JWKS, signing nothing. Waiting out the lead time so every verifier has had a chance to
    /// see it.
    /// </summary>
    Pending = 1,

    /// <summary>In JWKS and signing. Exactly one key per algorithm is ever in this state.</summary>
    Active = 2,

    /// <summary>
    /// Still in JWKS, no longer signing. Tokens it signed are still valid and must still verify.
    /// </summary>
    Retiring = 3,

    /// <summary>Out of JWKS. Every token it signed has expired.</summary>
    Retired = 4,
}

/// <summary>A key and where it is in its life.</summary>
/// <param name="Handle">The key material and its identifier.</param>
/// <param name="State">Which phase it is in.</param>
/// <param name="PublishedAt">When it entered <see cref="SigningKeyState.Pending"/>.</param>
/// <param name="ActivatedAt">When it began signing, if it has.</param>
public sealed record ManagedSigningKey(
    SigningKeyHandle Handle,
    SigningKeyState State,
    DateTimeOffset PublishedAt,
    DateTimeOffset? ActivatedAt = null);

/// <summary>Timings for key rotation.</summary>
public sealed class SigningKeyRingOptions
{
    /// <summary>
    /// How long a key sits in JWKS before it starts signing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This must exceed <b>the metadata cache lifetime plus the client's own staleness window</b>,
    /// and the arithmetic is not arbitrary: the discovery document is served with
    /// <c>max-age=300</c>, and Claude caches discovery globally with roughly a five-minute
    /// staleness window on top. A key that starts signing before that has elapsed signs tokens
    /// whose <c>kid</c> is unknown to every verifier that has not refetched.
    /// </para>
    /// <para>
    /// Ten minutes is the floor that arithmetic gives; the default is generous because there is no
    /// cost to waiting longer and the failure from waiting too little is a signature error nobody
    /// will diagnose as a rotation timing problem.
    /// </para>
    /// </remarks>
    public TimeSpan PublishLeadTime { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// How long a retiring key stays published after it stops signing.
    /// </summary>
    /// <remarks>
    /// Must be at least the maximum access-token lifetime, or a token signed a moment before
    /// rotation outlives the key that can verify it.
    /// </remarks>
    public TimeSpan RetentionAfterRetirement { get; set; } = TimeSpan.FromHours(24);

    /// <summary>The minimum <see cref="PublishLeadTime"/> the arithmetic above permits.</summary>
    public static TimeSpan MinimumPublishLeadTime { get; } = TimeSpan.FromMinutes(10);

    /// <summary>Validate, explaining the arithmetic rather than just refusing.</summary>
    public bool TryValidate(TimeSpan maxAccessTokenLifetime, out string? error)
    {
        error = null;

        if (PublishLeadTime < MinimumPublishLeadTime)
        {
            error =
                $"PublishLeadTime is {PublishLeadTime}, below the {MinimumPublishLeadTime} floor. " +
                "The discovery document is served with max-age=300 and clients add their own " +
                "staleness window of about five minutes on top, so a key that begins signing " +
                "sooner than that signs tokens whose kid no verifier has seen. The symptom is a " +
                "signature failure, which nobody diagnoses as a rotation timing problem.";
            return false;
        }

        if (RetentionAfterRetirement < maxAccessTokenLifetime)
        {
            error =
                $"RetentionAfterRetirement is {RetentionAfterRetirement} but an access token lives " +
                $"up to {maxAccessTokenLifetime}. A token signed just before rotation would outlive " +
                "the published key that verifies it.";
            return false;
        }

        return true;
    }
}

/// <summary>
/// The set of keys this server signs with and publishes.
/// </summary>
/// <remarks>
/// Time-based and stateless between instances: each one decides from the clock and the stored
/// state, so several replicas rotate consistently without coordinating.
/// </remarks>
public sealed class SigningKeyRing
{
    private readonly IReadOnlyList<ManagedSigningKey> _keys;
    private readonly SigningKeyRingOptions _options;
    private readonly TimeProvider _time;

    /// <summary>Create a ring over a known set of keys.</summary>
    public SigningKeyRing(
        IReadOnlyList<ManagedSigningKey> keys,
        SigningKeyRingOptions? options = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(keys);

        // Copied, not aliased. IReadOnlyList<T> is not immutable - a caller passing a List<T>
        // keeps a live handle - and this ring is captured once for the process lifetime while
        // PublishedKeys() runs on every JWKS request. Measured against the aliasing version:
        // clearing the caller's list emptied the JWKS, and mutating it during a poll threw
        // "Collection was modified". The obvious rotation implementation is the unsafe one.
        _keys = [.. keys];
        _options = options ?? new SigningKeyRingOptions();
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// How many keys are in <see cref="SigningKeyState.Active"/>, and therefore able to sign.
    /// </summary>
    /// <remarks>
    /// Exists for a gauge. <see cref="PublishedKeys"/> answers a different question - it includes
    /// <c>Pending</c> and <c>Retiring</c>, which is right for JWKS and wrong for "can this server
    /// still mint a token". <b>Zero here means it cannot</b>, and that is the number worth an alert:
    /// every other symptom of it arrives as a user being told to sign in again.
    /// </remarks>
    public int ActiveKeyCount => _keys.Count(k => k.State is SigningKeyState.Active);

    /// <summary>
    /// The key to sign with for an algorithm.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// No active key. Deliberately an exception rather than a silent fallback to a pending key:
    /// signing with a key nobody has fetched yet produces tokens that fail verification everywhere,
    /// which is a worse and much quieter failure than refusing to issue one.
    /// </exception>
    public SigningKeyHandle ActiveKey(SigningAlgorithm algorithm)
    {
        foreach (var key in _keys)
        {
            if (key.State is SigningKeyState.Active && key.Handle.Algorithm == algorithm)
            {
                return key.Handle;
            }
        }

        throw new InvalidOperationException(
            $"No active {algorithm} signing key. A pending key must not be used instead: verifiers " +
            "have not seen its kid yet, so every token signed with it would fail verification.");
    }

    /// <summary>
    /// Every key that belongs in JWKS: pending, active and retiring.
    /// </summary>
    /// <remarks>
    /// Pending keys are published - that is what makes them pending rather than unknown. Retiring
    /// keys are published because tokens they signed are still in flight. Only retired keys drop
    /// out.
    /// </remarks>
    public IReadOnlyList<SigningKeyHandle> PublishedKeys()
    {
        var published = new List<SigningKeyHandle>(_keys.Count);

        foreach (var key in _keys)
        {
            if (key.State is SigningKeyState.Pending or SigningKeyState.Active or SigningKeyState.Retiring)
            {
                published.Add(key.Handle);
            }
        }

        return published;
    }

    /// <summary>
    /// The public halves of <see cref="PublishedKeys"/>, for a resource server in this process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Public halves, not the handles.</b> A <see cref="SigningKeyHandle"/> holds the signing
    /// key - the private one - because minting is what it is for. Handing those to a bearer
    /// validator would work, since verification only touches the public half, but it would put the
    /// private key on the request path of a middleware that has no business holding it. This is the
    /// same discipline as the test asserting the JWKS body contains none of <c>d</c>, <c>p</c>,
    /// <c>q</c>, applied to an object graph instead of a response body.
    /// </para>
    /// <para>
    /// A fresh list every call, and that is the point: it is
    /// <c>ProtectedResourceOptions.SigningKeySource</c>'s producer, and a source exists so that a
    /// rotation publishes a new list rather than mutating one that requests are reading.
    /// </para>
    /// </remarks>
    public IReadOnlyList<SecurityKey> PublicVerificationKeys()
    {
        var published = PublishedKeys();
        var keys = new List<SecurityKey>(published.Count);

        foreach (var handle in published)
        {
            keys.Add(PublicHalfOf(handle));
        }

        return keys;
    }

    /// <summary>The verifying half of one key, labelled with the <c>kid</c> a token carries.</summary>
    /// <remarks>
    /// A key type this does not recognise is returned as it is rather than refused. Refusing would
    /// take a resource server offline over a key it could have verified with; the cost of not
    /// recognising one is that its private half stays in the object, which is the state every
    /// caller was in before this method existed.
    /// </remarks>
    private static SecurityKey PublicHalfOf(SigningKeyHandle handle) =>
        handle.Key switch
        {
            RsaSecurityKey { Rsa: not null } rsa =>
                new RsaSecurityKey(rsa.Rsa.ExportParameters(includePrivateParameters: false)) { KeyId = handle.Kid },
            ECDsaSecurityKey { ECDsa: not null } ec =>
                new ECDsaSecurityKey(ECDsa.Create(ec.ECDsa.ExportParameters(includePrivateParameters: false))) { KeyId = handle.Kid },
            _ => handle.Key,
        };

    /// <summary>
    /// Whether a pending key has waited long enough to start signing.
    /// </summary>
    public bool CanActivate(ManagedSigningKey key)
    {
        ArgumentNullException.ThrowIfNull(key);

        return key.State is SigningKeyState.Pending
            && _time.GetUtcNow() - key.PublishedAt >= _options.PublishLeadTime;
    }

    /// <summary>
    /// Whether a retiring key has been published long enough to drop out of JWKS.
    /// </summary>
    public bool CanRetire(ManagedSigningKey key, DateTimeOffset stoppedSigningAt)
    {
        ArgumentNullException.ThrowIfNull(key);

        return key.State is SigningKeyState.Retiring
            && _time.GetUtcNow() - stoppedSigningAt >= _options.RetentionAfterRetirement;
    }
}
