using Boltway.Storage.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Boltway.Storage.Sqlite;

/// <summary>Registers every store this package implements, over SQLite.</summary>
public static class SqliteStorageServiceCollectionExtensions
{
    /// <summary>
    /// Register the grant, code, refresh-token, consent and user stores against a SQLite database.
    /// </summary>
    /// <param name="services">The collection.</param>
    /// <param name="connectionString">The SQLite connection string.</param>
    /// <returns>The collection, for chaining.</returns>
    /// <remarks>
    /// <para>
    /// One call rather than seven, because seven is where a deployment forgets one — and the missing
    /// piece would not be a store but <see cref="IRelationalStoreBehavior"/>, whose absence is the
    /// one that produces a race rather than a startup error.
    /// </para>
    /// <para>
    /// <b>A factory, not a scoped context.</b> The stores are singletons and a <c>DbContext</c> is
    /// not thread-safe, so each store call takes its own context and its own connection. That is
    /// also what lets a redemption hold a write transaction without blocking an unrelated read on
    /// the same request.
    /// </para>
    /// <para>
    /// <b>This does not create or migrate the database.</b> <c>DESIGN.md</c> §1.2 keeps migrations
    /// off the request path: three replicas racing <c>Database.Migrate()</c> at startup is an
    /// outage, and <c>C-29</c> forbids a synchronous migration on a request. Run
    /// <c>dotnet ef database update</c> as a deploy step.
    /// </para>
    /// <para>
    /// <b>Connection pooling is turned off for a file database, and that is a correctness setting
    /// rather than a tuning one.</b> Measured: <c>Microsoft.Data.Sqlite</c> does not clean a handle
    /// on its way back to the pool, so a connection returned while its <i>native</i> handle is
    /// inside a transaction comes back out still inside it, and the next <c>BEGIN IMMEDIATE</c>
    /// fails with <c>SQLite Error 1: 'cannot start a transaction within a transaction'</c> — the
    /// intermittent defect documented on <see cref="SqliteRelationalStoreBehavior"/>. Without a
    /// pool there is no handle to recycle and that mechanism cannot occur.
    /// </para>
    /// <para>
    /// <b>What this is not:</b> a demonstrated fix. What puts a handle back mid-transaction has not
    /// been found, so this removes the only route that has been proven to exist rather than the
    /// cause. The flake rate is the measurement to watch. The cost is a file open per store call,
    /// which for a provider that is development-only is not a cost worth a race.
    /// </para>
    /// <para>
    /// It overrides an explicit <c>Pooling=True</c>, deliberately. An in-memory database is left
    /// alone: without a pool, closing the last connection destroys it.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddBoltwaySqliteStores(
        this IServiceCollection services, string connectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        var builder = new SqliteConnectionStringBuilder(connectionString);

        if (builder.Mode is not SqliteOpenMode.Memory
            && !string.Equals(builder.DataSource, ":memory:", StringComparison.OrdinalIgnoreCase))
        {
            builder.Pooling = false;
        }

        var normalised = builder.ConnectionString;

        // Named explicitly: the migrations live in this assembly, not beside the DbContext, because
        // two providers cannot share one migration history past the first ALTER COLUMN.
        var migrations = typeof(SqliteStorageServiceCollectionExtensions).Assembly.FullName;

        services.AddDbContextFactory<AuthDbContext>(options =>
            options.UseSqlite(normalised, sqlite => sqlite.MigrationsAssembly(migrations)));

        services.TryAddSingleton<IRelationalStoreBehavior, SqliteRelationalStoreBehavior>();
        services.AddBoltwayEntityFrameworkStores();

        return services;
    }
}
