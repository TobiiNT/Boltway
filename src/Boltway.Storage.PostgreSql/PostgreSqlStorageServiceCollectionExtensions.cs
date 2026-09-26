using Boltway.Storage.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;

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
    /// One call rather than seven, because seven is where a deployment forgets one - and the missing
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
    /// there is nothing for a retry policy to retry - it takes the lock rather than gambling on an
    /// optimistic isolation level, so contention is bounded waiting rather than a
    /// <c>40001</c> a caller has no case for.
    /// </para>
    /// <para>
    /// <b>This does not create or migrate the database.</b> <c>DESIGN.md</c> §1.2 keeps migrations
    /// off the request path: three replicas racing <c>Database.Migrate()</c> at startup is an
    /// outage, and <c>C-29</c> forbids a synchronous migration on a request. Run
    /// <c>dotnet ef database update</c> as a deploy step.
    /// </para>
    /// <para>
    /// <b>GSS encryption is off unless the deployment names it.</b> A connection string naming no
    /// <c>GSS Encryption Mode</c>, in a process whose <c>PGGSSENCMODE</c> names none either, reaches
    /// Npgsql with <c>GSS Encryption Mode=Disable</c>.
    /// <see cref="PostgreSqlStorageOptions.DisableGssEncryptionByDefault"/> says why and turns it
    /// off; this overload takes every default. Filling it in parses the string here, so one Npgsql
    /// cannot parse is refused by this call rather than by the first connection.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddBoltwayPostgreSqlStores(
        this IServiceCollection services, string connectionString) =>
        services.AddBoltwayPostgreSqlStores(connectionString, static _ => { });

    /// <summary>
    /// Register the grant, code, refresh-token, consent and user stores against a PostgreSQL
    /// database, adjusting what happens to the connection string on the way.
    /// </summary>
    /// <param name="services">The collection.</param>
    /// <param name="connectionString">The Npgsql connection string.</param>
    /// <param name="configure">Changes the options before they are read, once, during this call.</param>
    /// <returns>The collection, for chaining.</returns>
    /// <remarks>
    /// Everything said on
    /// <see cref="AddBoltwayPostgreSqlStores(IServiceCollection, string)"/> holds here too; that
    /// overload is this one with nothing changed.
    /// </remarks>
    public static IServiceCollection AddBoltwayPostgreSqlStores(
        this IServiceCollection services, string connectionString, Action<PostgreSqlStorageOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(configure);

        var storage = new PostgreSqlStorageOptions();
        configure(storage);

        var effective = storage.DisableGssEncryptionByDefault
            ? WithGssEncryptionDisabledUnlessNamed(connectionString)
            : connectionString;

        // Named explicitly: the migrations live in this assembly, not beside the DbContext, because
        // two providers cannot share one migration history past the first ALTER COLUMN.
        var migrations = typeof(PostgreSqlStorageServiceCollectionExtensions).Assembly.FullName;

        services.AddDbContextFactory<AuthDbContext>(options =>
            options.UseNpgsql(effective, npgsql => npgsql.MigrationsAssembly(migrations)));

        services.TryAddSingleton<IRelationalStoreBehavior, PostgreSqlRelationalStoreBehavior>();
        services.AddBoltwayEntityFrameworkStores();

        return services;
    }

    /// <summary>
    /// <paramref name="connectionString"/>, with <c>GSS Encryption Mode=Disable</c> added when
    /// nothing Npgsql reads names a mode.
    /// </summary>
    private static string WithGssEncryptionDisabledUnlessNamed(string connectionString)
    {
        var builder = new NpgsqlConnectionStringBuilder(connectionString);

        // Remove answers "did the string set this" under every spelling Npgsql accepts for the key,
        // and nameof keeps the keyword tied to the property rather than to a spelling typed here. The
        // obvious members do not answer it: ContainsKey says whether the keyword exists at all and is
        // true of one nobody wrote, and the property reads Prefer both when a deployment wrote Prefer
        // and when it wrote nothing. Both measured on Npgsql 10.0.3. When it removed something the
        // original string is returned rather than this builder, so a named mode goes through exactly
        // as written; when it removed nothing, it changed nothing.
        if (builder.Remove(nameof(NpgsqlConnectionStringBuilder.GssEncryptionMode)))
        {
            return connectionString;
        }

        // Npgsql's own second tier, read with the same parse it applies (NpgsqlConnector.GetGssEncMode
        // in 10.0.3), so a value it would honour is left for it and one it would ignore is replaced
        // like an absent one.
        if (Enum.TryParse<GssEncryptionMode>(
                Environment.GetEnvironmentVariable("PGGSSENCMODE"), ignoreCase: true, out _))
        {
            return connectionString;
        }

        builder.GssEncryptionMode = GssEncryptionMode.Disable;

        return builder.ConnectionString;
    }
}
