using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.Storage.InMemory;
using Boltway.Storage.Testing;

namespace Boltway.Storage.Tests;

// This repository's own derivations of the contracts in Boltway.Storage.Testing, run against the
// in-memory stores.
//
// They live here rather than beside the contracts because of what shipping them did: packaged
// together, a customer referencing the storage contract suite got these seven classes in their own
// `dotnet test` run and read Boltway's results as being about their store. The contracts are a
// surface somebody else derives from; these are tests only this repository is held to, and the two
// belong in different assemblies for the same reason the interaction contracts already do.

/// <summary>The in-memory implementation against the contract.</summary>
public sealed class InMemoryAdminAuditStoreTests : AdminAuditStoreContract
{
    /// <inheritdoc />
    protected override IAdminAuditStore NewAuditStore() => new InMemory.InMemoryAdminAuditStore();
}

/// <summary>The replay contract, against the in-memory store.</summary>
public sealed class InMemoryClientAssertionReplayStoreTests : ClientAssertionReplayStoreContract
{
    /// <inheritdoc />
    protected override IClientAssertionReplayStore NewReplayStore() => new InMemoryClientAssertionReplayStore();
}

/// <summary>The client-store contract, against the in-memory store.</summary>
public sealed class InMemoryClientStoreTests : ClientStoreContract
{
    /// <inheritdoc />
    protected override IClientStore NewClientStore() => new InMemory.InMemoryClientStore();
}

/// <summary>The contract, against the in-memory store.</summary>
public sealed class InMemoryConsentStoreTests : ConsentStoreContract
{
    protected override IConsentStore NewConsentStore() => new InMemory.InMemoryConsentStore();
}

/// <summary>The contract, against the in-memory store.</summary>
public sealed class InMemoryGrantStoreTests : GrantStoreContract
{
    // A fresh store per call, not one shared instance. The repeated concurrency tests need an
    // empty store each iteration, and sharing one also lets a test see rows another test wrote.
    protected override IAuthorizationCodeStore NewCodeStore() => new InMemory.InMemoryAuthorizationCodeStore();

    protected override IRefreshTokenStore NewRefreshStore() => new InMemory.InMemoryRefreshTokenStore();

    protected override IGrantStore NewGrantStore() => new InMemory.InMemoryGrantStore();
}

/// <summary>The contract, against the in-memory store.</summary>
public sealed class InMemoryUserStoreTests : UserStoreContract
{
    // A fresh store per call, so no test can see a row another test wrote.
    protected override (IUserStore Users, IRoleStore Roles) NewStores()
    {
        var roles = new InMemory.InMemoryRoleStore();

        return (new InMemory.InMemoryUserStore(roles), roles);
    }
}

/// <summary>The contract, against the in-memory store.</summary>
public sealed class InMemoryUserTokenStoreTests : UserTokenStoreContract
{
    protected override IUserTokenStore NewTokenStore() => new InMemory.InMemoryUserTokenStore();
}
