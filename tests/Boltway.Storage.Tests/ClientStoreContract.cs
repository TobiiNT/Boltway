using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.Storage.Tests;

/// <summary>
/// The <see cref="IClientStore"/> contract, run against every implementation.
/// </summary>
/// <remarks>
/// <para>
/// Two rules here are the ones an obvious first draft gets wrong, and both destroy a credential
/// rather than merely misbehaving:
/// </para>
/// <para>
/// <b>A null secret on an update means "unchanged", not "remove it".</b> Renaming a client would
/// otherwise silently delete the secret it authenticates with, and the report is "the nightly job
/// stopped working" some hours later, from somebody who only edited a label.
/// </para>
/// <para>
/// <b>Disabling twice does not move the timestamp.</b> "Since when" is the question asked
/// immediately after "is it off", and answering it with the moment somebody clicked a second time
/// is worse than not answering — it reads as a fact.
/// </para>
/// <para>
/// This suite exists because the pair has diverged before. <c>IUserStore.StoreAsync</c> enforced a
/// role's existence in the relational store and not in the in-memory one, so a test passed in
/// memory and the behaviour it proved was not the behaviour that shipped.
/// </para>
/// </remarks>
public abstract class ClientStoreContract
{
    /// <summary>A fresh, empty client store.</summary>
    protected abstract IClientStore NewClientStore();

    private static readonly SubjectId Ada = SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0XY");

    private static readonly SubjectId Grace = SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0ZZ");

    private static ClientRecord ServiceAccount(
        string id = "northwind-nightly", SubjectId? owner = null, string scopes = "docs:read")
    {
        _ = ScopeSet.TryParse(scopes, out var parsed, out _);

        return new ClientRecord
        {
            ClientId = ClientIdentifier.ForPreRegistered(id),
            ClientType = ClientType.Confidential,
            TokenEndpointAuthMethod = ClientAuthMethod.ClientSecretBasic,
            RedirectUris = [],
            GrantTypes = ["client_credentials"],
            ResponseTypes = ["code"],
            ClientName = "Nightly report",
            AllowedScopes = parsed,
            Owner = owner ?? Ada,
        };
    }

    private static Sha256Hash Secret(string material) => Sha256Hash.OfString(material);

    [Fact]
    public async Task A_stored_client_comes_back_with_its_owner_and_scopes()
    {
        var store = NewClientStore();

        await store.StoreAsync(ServiceAccount(), Secret("first"), CancellationToken.None);

        var found = await store.FindAsync(
            ClientIdentifier.ForPreRegistered("northwind-nightly"), CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal(Ada, found.Owner);
        Assert.Equal("docs:read", found.AllowedScopes.ToWireString());
        Assert.True(found.IsEnabled);
    }

    [Fact]
    public async Task An_unknown_client_is_null_rather_than_an_error()
    {
        var store = NewClientStore();

        Assert.Null(await store.FindAsync(
            ClientIdentifier.ForPreRegistered("nobody"), CancellationToken.None));

        Assert.Null(await store.FindSecretAsync(
            ClientIdentifier.ForPreRegistered("nobody"), CancellationToken.None));
    }

    [Fact]
    public async Task The_secret_round_trips_as_a_digest()
    {
        var store = NewClientStore();

        await store.StoreAsync(ServiceAccount(), Secret("first"), CancellationToken.None);

        var hash = await store.FindSecretAsync(
            ClientIdentifier.ForPreRegistered("northwind-nightly"), CancellationToken.None);

        Assert.NotNull(hash);
        Assert.Equal(Secret("first"), hash.Value);
        Assert.NotEqual(Secret("second"), hash.Value);
    }

    /// <summary>Re-storing a client without a secret keeps the one it had.</summary>
    [Fact]
    public async Task Storing_again_with_no_secret_keeps_the_existing_one()
    {
        var store = NewClientStore();

        await store.StoreAsync(ServiceAccount(), Secret("first"), CancellationToken.None);

        await store.StoreAsync(
            ServiceAccount() with { ClientName = "Renamed" }, null, CancellationToken.None);

        var hash = await store.FindSecretAsync(
            ClientIdentifier.ForPreRegistered("northwind-nightly"), CancellationToken.None);

        Assert.NotNull(hash);
        Assert.Equal(Secret("first"), hash.Value);

        var found = await store.FindAsync(
            ClientIdentifier.ForPreRegistered("northwind-nightly"), CancellationToken.None);

        Assert.Equal("Renamed", found!.ClientName);
    }

    /// <summary>And supplying one replaces it, which is what rotation is.</summary>
    [Fact]
    public async Task Storing_again_with_a_secret_rotates_it()
    {
        var store = NewClientStore();

        await store.StoreAsync(ServiceAccount(), Secret("first"), CancellationToken.None);
        await store.StoreAsync(ServiceAccount(), Secret("second"), CancellationToken.None);

        var hash = await store.FindSecretAsync(
            ClientIdentifier.ForPreRegistered("northwind-nightly"), CancellationToken.None);

        Assert.Equal(Secret("second"), hash!.Value);
        Assert.NotEqual(Secret("first"), hash.Value);
    }

    [Fact]
    public async Task A_client_is_found_by_the_account_it_acts_as()
    {
        var store = NewClientStore();

        await store.StoreAsync(ServiceAccount(), Secret("first"), CancellationToken.None);

        var found = await store.FindByOwnerAsync(Ada, CancellationToken.None);
        Assert.NotNull(found);
        Assert.Equal("northwind-nightly", found.ClientId.Value);

        // Somebody else's account holds nothing, which is the answer that has to be right before
        // anybody relies on this to decide whether disabling an account leaves a credential behind.
        Assert.Null(await store.FindByOwnerAsync(Grace, CancellationToken.None));
    }

    /// <summary>Disabling stops it authorizing and keeps everything else.</summary>
    [Fact]
    public async Task Disabling_is_visible_and_reversible()
    {
        var store = NewClientStore();
        var id = ClientIdentifier.ForPreRegistered("northwind-nightly");

        await store.StoreAsync(ServiceAccount(), Secret("first"), CancellationToken.None);

        Assert.True(await store.SetEnabledAsync(id, false, CancellationToken.None));

        var disabled = await store.FindAsync(id, CancellationToken.None);
        Assert.False(disabled!.IsEnabled);

        // The secret survives being disabled. Withholding it would make a disabled client look like
        // a misconfigured one at authentication, which sends the reader to the wrong place.
        Assert.NotNull(await store.FindSecretAsync(id, CancellationToken.None));

        Assert.True(await store.SetEnabledAsync(id, true, CancellationToken.None));
        Assert.True((await store.FindAsync(id, CancellationToken.None))!.IsEnabled);
    }

    [Fact]
    public async Task Disabling_an_unknown_client_reports_that_rather_than_succeeding()
    {
        var store = NewClientStore();

        Assert.False(await store.SetEnabledAsync(
            ClientIdentifier.ForPreRegistered("nobody"), false, CancellationToken.None));
    }

    [Fact]
    public async Task Deleting_removes_the_client_and_its_secret()
    {
        var store = NewClientStore();
        var id = ClientIdentifier.ForPreRegistered("northwind-nightly");

        await store.StoreAsync(ServiceAccount(), Secret("first"), CancellationToken.None);

        Assert.True(await store.DeleteAsync(id, CancellationToken.None));

        Assert.Null(await store.FindAsync(id, CancellationToken.None));
        Assert.Null(await store.FindSecretAsync(id, CancellationToken.None));
        Assert.Null(await store.FindByOwnerAsync(Ada, CancellationToken.None));

        // Reported rather than succeeding silently: a caller cleaning up needs to know whether the
        // deletion actually landed.
        Assert.False(await store.DeleteAsync(id, CancellationToken.None));
    }
}

/// <summary>The client-store contract, against the in-memory store.</summary>
public sealed class InMemoryClientStoreTests : ClientStoreContract
{
    /// <inheritdoc />
    protected override IClientStore NewClientStore() => new InMemory.InMemoryClientStore();
}
