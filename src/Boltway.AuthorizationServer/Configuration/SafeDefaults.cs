using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Token;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.AuthorizationServer.Configuration;

/// <summary>
/// Always ask the user. The default <see cref="IConsentPolicy"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="IConsentPolicy"/> was required and had no implementation, so every deployment had to
/// write one before the server would answer a request - and the obvious first draft, "if a consent
/// record exists then <see cref="ConsentDecision.AlreadyGranted"/>", is subtly wrong: it grants
/// whatever the current request asks for on the strength of a record that may cover far less. A
/// review executed that draft and obtained a token for a resource the user had never seen.
/// </para>
/// <para>
/// So the shipped default asks every time. It is the only answer that is correct without knowing
/// anything about the deployment: it can annoy a user, and it cannot authorize something they did
/// not look at. A customer who wants "do not re-ask for our own first-party client" is making a
/// real policy decision and should write it down, which is what the seam is for - and when they do,
/// the comparison they owe is <see cref="ConsentContext.RequestedScope"/> and
/// <see cref="ConsentContext.RequestedResources"/> against <see cref="ConsentContext.Existing"/>,
/// not merely whether <c>Existing</c> is non-null.
/// </para>
/// <para>
/// Registered with <c>TryAdd</c>, so a policy the host registers first wins. Whatever is registered
/// is still wrapped in <c>PublicClientReconsentGuard</c> at the call site, which a customer cannot
/// remove.
/// </para>
/// </remarks>
public sealed class AlwaysAskConsentPolicy : IConsentPolicy
{
    /// <inheritdoc />
    public ValueTask<ConsentDecision> DecideAsync(ConsentContext context, CancellationToken cancellationToken) =>
        ValueTask.FromResult(ConsentDecision.Required);
}

/// <summary>
/// No client has a secret. The default <see cref="IClientSecretStore"/>.
/// </summary>
/// <remarks>
/// <para>
/// The token endpoint resolves <see cref="IClientSecretStore"/> unconditionally, so a deployment of
/// nothing but public CIMD clients - which is what both vendors' MCP clients are, and what this
/// server is primarily for - still had to write one before it could issue a token. Measured: a
/// public client declaring <c>token_endpoint_auth_method: none</c> threw at <c>/token</c> for want
/// of a store it never consults.
/// </para>
/// <para>
/// Answering <see langword="null"/> is not a weakening. The contract already defines
/// <see langword="null"/> as "this client has no secret", and a client that presents a secret
/// against it fails authentication - so the default fails closed. A confidential client is what
/// needs a real store, and a deployment with one knows it has one.
/// </para>
/// </remarks>
public sealed class NoClientSecretsStore : IClientSecretStore
{
    /// <inheritdoc />
    public Task<Sha256Hash?> FindAsync(ClientIdentifier clientId, CancellationToken cancellationToken) =>
        Task.FromResult<Sha256Hash?>(null);
}
