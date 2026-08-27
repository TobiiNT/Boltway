using Boltway.Storage.Sqlite;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.Storage.Sqlite.Tests;

/// <summary>
/// A fresh, migrated SQLite database per call, and the cleanup for them.
/// </summary>
/// <remarks>
/// <para>
/// <b>Files, not <c>:memory:</c>.</b> Keeping an in-memory database alive across connections needs
/// shared cache, and shared cache is a different locking model from the one a deployment runs:
/// SQLite documents it as locking at table granularity and raising <c>SQLITE_LOCKED</c>, which the
/// busy handler is not invoked for. The concurrency tests here are about what happens when writers
/// collide, so they have to collide the way they will in production. That was not measured - the
/// point is that it would be measuring the wrong thing, which is a reason not to find out the hard
/// way. The contract's own remarks make the same argument about threads.
/// </para>
/// <para>
/// <b>Migrated once, then copied.</b> <c>NewCodeStore()</c> is called inside loops that run up to
/// 200 iterations, so the migration would run 200 times. The template is built by the same
/// <c>Database.Migrate()</c> a deployment runs, so what the contract runs against is the migration's
/// output rather than <c>EnsureCreated</c>'s.
/// </para>
/// </remarks>
internal sealed class SqliteDatabases : IDisposable
{
    private static readonly Lazy<string> Template = new(BuildTemplate, LazyThreadSafetyMode.ExecutionAndPublication);

    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), "boltway-storage-tests", Guid.NewGuid().ToString("N"));

    private readonly List<(ServiceProvider Provider, string ConnectionString)> _created = [];

    /// <summary>A service provider whose stores talk to a brand-new empty database.</summary>
    public IServiceProvider New()
    {
        Directory.CreateDirectory(_directory);

        var path = Path.Combine(_directory, Guid.NewGuid().ToString("N") + ".db");
        File.Copy(Template.Value, path);

        var connectionString = $"Data Source={path}";
        var services = new ServiceCollection();

        // Through the extension a host would call, so the wiring is under test too rather than
        // hand-assembled here where a missing registration would never be noticed.
        services.AddBoltwaySqliteStores(connectionString);

        var provider = services.BuildServiceProvider();
        _created.Add((provider, connectionString));

        return provider;
    }

    public void Dispose()
    {
        foreach (var (provider, connectionString) in _created)
        {
            provider.Dispose();

            // Pooled connections keep the file open, so the delete below fails without this.
            // ClearPool rather than ClearAllPools: test classes run in parallel and the static
            // version would close connections another class is using.
            using var handle = new SqliteConnection(connectionString);
            SqliteConnection.ClearPool(handle);
        }

        _created.Clear();

        try
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
        catch (IOException)
        {
            // A leftover file in the temp directory is not worth failing a green test over.
        }
    }

    private static string BuildTemplate()
    {
        var directory = Path.Combine(Path.GetTempPath(), "boltway-storage-tests", "template");
        Directory.CreateDirectory(directory);

        var path = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".db");
        var connectionString = $"Data Source={path}";

        var services = new ServiceCollection();
        services.AddBoltwaySqliteStores(connectionString);

        using (var provider = services.BuildServiceProvider())
        {
            var factory = provider.GetRequiredService<IDbContextFactory<EntityFrameworkCore.AuthDbContext>>();
            using var context = factory.CreateDbContext();
            context.Database.Migrate();
        }

        using var handle = new SqliteConnection(connectionString);
        SqliteConnection.ClearPool(handle);

        return path;
    }
}
