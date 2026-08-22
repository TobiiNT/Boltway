using Boltway.Storage.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Boltway.Storage.PostgreSql;

/// <summary>Registers every store this package implements, over PostgreSQL.</summary>
public static class PostgreSqlStorageServiceCollectionExtensions
{
    /// <summary>
    /// Register the grant, code, refresh-token, consent and user stores against a PostgreSQL
    /// database.
    /// </summary>
    /// <param name="services">The collection.</param>
    /// <param name="connectionString">The Npgsql connection string.</param>
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
    /// <b><c>EnableRetryOnFailure</c> is not configured here, and that is deliberate.</b>
    /// <c>DESIGN.md</c> §1.2 keeps it off on <c>/token</c>: a retry inside a ten-second budget turns
    /// a fast failure into a timeout. <see cref="PostgreSqlRelationalStoreBehavior"/> is built so
    /// there is nothing for a retry policy to retry — it takes the lock rather than gambling on an
    /// optimistic isolation level, so contention is bounded waiting rather than a
    /// <c>40001</c> a caller has no case for.
    /// </para>
    /// <para>
    /// <b>This does not create or migrate the database.</b> <c>DESIGN.md</c> §1.2 keeps migrations
    /// off the request path: three replicas racing <c>Database.Migrate()</c> at startup is an
    /// outage, and <c>C-29</c> forbids a synchronous migration on a request. Run
    /// <c>dotnet ef database update</c> as a deploy step.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddBoltwayPostgreSqlStores(
        this IServiceCollection services, string connectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        // Named explicitly: the migrations live in this assembly, not beside the DbContext, because
        // two providers cannot share one migration history past the first ALTER COLUMN.
        var migrations = typeof(PostgreSqlStorageServiceCollectionExtensions).Assembly.FullName;

        services.AddDbContextFactory<AuthDbContext>(options =>
            options.UseNpgsql(connectionString, npgsql => npgsql.MigrationsAssembly(migrations)));

        services.TryAddSingleton<IRelationalStoreBehavior, PostgreSqlRelationalStoreBehavior>();
        services.AddBoltwayEntityFrameworkStores();

        return services;
    }
}
