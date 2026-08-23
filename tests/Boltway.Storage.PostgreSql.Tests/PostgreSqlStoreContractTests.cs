using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.Storage.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.Storage.PostgreSql.Tests;

/// <summary>
/// The grant-store contract, against a live PostgreSQL server.
/// </summary>
/// <remarks>
/// <para>
/// The three concurrency tests here are the reason this project exists rather than being a second
/// copy of the SQLite one. SQLite admits one writer at a time whatever the code does, so
/// <c>BEGIN IMMEDIATE</c> is a correction to a lock the engine was going to take anyway. PostgreSQL
/// admits as many concurrent writers as there are connections, so on this provider the atomicity in
/// <see cref="PostgreSqlRelationalStoreBehavior"/> is the only thing between four threads and a
/// forked refresh-token family.
/// </para>
/// </remarks>
public sealed class PostgreSqlGrantStoreTests(PostgresDatabase database)
    : GrantStoreContract, IClassFixture<PostgresDatabase>
{
    /// <inheritdoc />
    protected override IAuthorizationCodeStore NewCodeStore() =>
        database.New().GetRequiredService<IAuthorizationCodeStore>();

    /// <inheritdoc />
    protected override IRefreshTokenStore NewRefreshStore() =>
        database.New().GetRequiredService<IRefreshTokenStore>();

    /// <inheritdoc />
    protected override IGrantStore NewGrantStore() =>
        database.New().GetRequiredService<IGrantStore>();
}

/// <summary>The user-store contract, against a live PostgreSQL server.</summary>
public sealed class PostgreSqlUserStoreTests(PostgresDatabase database)
    : UserStoreContract, IClassFixture<PostgresDatabase>
{
    /// <inheritdoc />
    protected override (IUserStore Users, IRoleStore Roles) NewStores()
    {
        var services = database.New();

        return (services.GetRequiredService<IUserStore>(), services.GetRequiredService<IRoleStore>());
    }
}

/// <summary>The consent-store contract, against a live PostgreSQL server.</summary>
public sealed class PostgreSqlConsentStoreTests(PostgresDatabase database)
    : ConsentStoreContract, IClassFixture<PostgresDatabase>
{
    /// <inheritdoc />
    protected override IConsentStore NewConsentStore() => database.New().GetRequiredService<IConsentStore>();
}

/// <summary>The audit-log contract, against a live PostgreSQL server.</summary>
public sealed class PostgreSqlAdminAuditStoreTests(PostgresDatabase database)
    : AdminAuditStoreContract, IClassFixture<PostgresDatabase>
{
    /// <inheritdoc />
    protected override AuthorizationServer.Abstractions.Administration.IAdminAuditStore NewAuditStore() =>
        database.New().GetRequiredService<AuthorizationServer.Abstractions.Administration.IAdminAuditStore>();
}

/// <summary>The one-time-link contract, against a live PostgreSQL server.</summary>
public sealed class PostgreSqlUserTokenStoreTests(PostgresDatabase database)
    : UserTokenStoreContract, IClassFixture<PostgresDatabase>
{
    /// <inheritdoc />
    protected override IUserTokenStore NewTokenStore() => database.New().GetRequiredService<IUserTokenStore>();
}

/// <summary>The client-store contract, against a live PostgreSQL server.</summary>
public sealed class PostgreSqlClientStoreTests(PostgresDatabase database)
    : ClientStoreContract, IClassFixture<PostgresDatabase>
{
    /// <inheritdoc />
    protected override IClientStore NewClientStore() => database.New().GetRequiredService<IClientStore>();
}

/// <summary>The client-assertion replay contract, against a live PostgreSQL server.</summary>
public sealed class PostgreSqlClientAssertionReplayStoreTests(PostgresDatabase database)
    : ClientAssertionReplayStoreContract, IClassFixture<PostgresDatabase>
{
    /// <inheritdoc />
    protected override IClientAssertionReplayStore NewReplayStore() =>
        database.New().GetRequiredService<IClientAssertionReplayStore>();
}
