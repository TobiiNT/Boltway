using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.Storage.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.Storage.Sqlite.Tests;

/// <summary>
/// The grant-store contract, against SQLite.
/// </summary>
/// <remarks>
/// The suite that had exactly one derived class until now, and that class was a dictionary behind a
/// lock. Everything the contract says about atomicity — one winner out of sixteen concurrent
/// redemptions, a family that does not fork, a sweeper that does not remove a row a redemption just
/// wrote — was true of the in-memory store because a <c>lock</c> makes it true, and untested
/// anywhere a transaction has to make it true instead.
/// </remarks>
public sealed class SqliteGrantStoreTests : GrantStoreContract, IDisposable
{
    private readonly SqliteDatabases _databases = new();

    /// <inheritdoc />
    protected override IAuthorizationCodeStore NewCodeStore() =>
        _databases.New().GetRequiredService<IAuthorizationCodeStore>();

    /// <inheritdoc />
    protected override IRefreshTokenStore NewRefreshStore() =>
        _databases.New().GetRequiredService<IRefreshTokenStore>();

    /// <inheritdoc />
    protected override IGrantStore NewGrantStore() =>
        _databases.New().GetRequiredService<IGrantStore>();

    /// <inheritdoc />
    public void Dispose() => _databases.Dispose();
}

/// <summary>The user-store contract, against SQLite.</summary>
public sealed class SqliteUserStoreTests : UserStoreContract, IDisposable
{
    private readonly SqliteDatabases _databases = new();

    /// <inheritdoc />
    protected override (IUserStore Users, IRoleStore Roles) NewStores()
    {
        var services = _databases.New();

        return (services.GetRequiredService<IUserStore>(), services.GetRequiredService<IRoleStore>());
    }

    /// <inheritdoc />
    public void Dispose() => _databases.Dispose();
}

/// <summary>The consent-store contract, against SQLite.</summary>
public sealed class SqliteConsentStoreTests : ConsentStoreContract, IDisposable
{
    private readonly SqliteDatabases _databases = new();

    /// <inheritdoc />
    protected override IConsentStore NewConsentStore() => _databases.New().GetRequiredService<IConsentStore>();

    /// <inheritdoc />
    public void Dispose() => _databases.Dispose();
}

/// <summary>The audit-log contract, against SQLite.</summary>
public sealed class SqliteAdminAuditStoreTests : AdminAuditStoreContract, IDisposable
{
    private readonly SqliteDatabases _databases = new();

    /// <inheritdoc />
    protected override AuthorizationServer.Abstractions.Administration.IAdminAuditStore NewAuditStore() =>
        _databases.New().GetRequiredService<AuthorizationServer.Abstractions.Administration.IAdminAuditStore>();

    /// <inheritdoc />
    public void Dispose() => _databases.Dispose();
}

/// <summary>The one-time-link contract, against Sqlite.</summary>
public sealed class SqliteUserTokenStoreTests : UserTokenStoreContract, IDisposable
{
    private readonly SqliteDatabases _databases = new();

    /// <inheritdoc />
    protected override IUserTokenStore NewTokenStore() =>
        _databases.New().GetRequiredService<IUserTokenStore>();

    /// <inheritdoc />
    public void Dispose() => _databases.Dispose();
}

/// <summary>The client-store contract, against SQLite.</summary>
public sealed class SqliteClientStoreTests : ClientStoreContract, IDisposable
{
    private readonly SqliteDatabases _databases = new();

    /// <inheritdoc />
    protected override IClientStore NewClientStore() => _databases.New().GetRequiredService<IClientStore>();

    /// <inheritdoc />
    public void Dispose() => _databases.Dispose();
}

/// <summary>The client-assertion replay contract, against SQLite.</summary>
public sealed class SqliteClientAssertionReplayStoreTests : ClientAssertionReplayStoreContract, IDisposable
{
    private readonly SqliteDatabases _databases = new();

    /// <inheritdoc />
    protected override IClientAssertionReplayStore NewReplayStore() =>
        _databases.New().GetRequiredService<IClientAssertionReplayStore>();

    /// <inheritdoc />
    public void Dispose() => _databases.Dispose();
}
