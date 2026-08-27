using System.Globalization;
using Boltway.Storage.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Boltway.Storage.PostgreSql.Tests;

/// <summary>
/// One real, migrated PostgreSQL database for a test class, and an empty one for every call.
/// </summary>
/// <remarks>
/// <para>
/// <b>A real server, and no way to pretend otherwise.</b> If the server is not reachable the
/// constructor throws, xUnit reports every test in the class as <i>failed</i> with that exception,
/// and nothing in this assembly is ever reported as skipped. That is deliberate: a storage suite
/// that skips itself when the database is missing reads as green in exactly the situation where it
/// measured nothing, which is the failure <c>LESSONS.md</c> is a ledger of. The cost is that
/// <c>dotnet test</c> needs a PostgreSQL server; the connection string is overridable through
/// <c>BOLTWAY_TEST_POSTGRES</c>.
/// </para>
/// <para>
/// <b>A class fixture, so the database is created once per test class rather than once per test.</b>
/// <c>CREATE DATABASE</c> costs about 130 ms on the machine this was written on and
/// <c>GrantStoreContract</c> asks for a fresh store roughly 345 times, so a database per call would
/// spend a minute and a half creating and dropping them. xUnit runs the tests of one class
/// sequentially and different classes in parallel, so a database per class is still a database per
/// thing that could collide with another: no two tests are ever inside the same one at the same
/// time, which matters here because the lock this provider takes is table-wide.
/// </para>
/// <para>
/// <b><see cref="New"/> empties the database rather than making a new one.</b> Measured on this
/// machine: <c>TRUNCATE</c> of all seven tables in one statement is about 18 ms, against about 260 ms
/// to create and drop a database. The tables come from the model rather than from a list typed here,
/// because a table added to <see cref="AuthDbContext"/> and forgotten in such a list would leave rows
/// visible to the next call, and that surfaces as an unrelated test failing sometimes.
/// </para>
/// <para>
/// <b>What that costs, stated rather than assumed:</b> every test in the three shared contracts calls
/// exactly one of the <c>New…Store</c> methods, so emptying on each call is invisible to them. A test
/// added later that took a code store and a refresh store and expected both to see the same database
/// would find the first one's rows gone. It would <i>fail</i>, loudly, on an assertion about a row
/// that is not there - not pass quietly - which is why this is worth the speed rather than being a
/// trap.
/// </para>
/// </remarks>
public sealed class PostgresDatabase : IDisposable
{
    /// <summary>
    /// Where the server is.
    /// </summary>
    /// <remarks>
    /// <c>Maximum Pool Size</c> is set down from Npgsql's default of 100 because a stock PostgreSQL
    /// allows 100 connections in total and xUnit runs this assembly's four test classes in parallel,
    /// each against its own database and therefore its own pool. Twenty apiece leaves headroom and
    /// still exceeds the sixteen threads
    /// <c>Redeeming_many_times_in_parallel_still_succeeds_exactly_once</c> collides with, so the
    /// pool is not what serialises them.
    /// </remarks>
    private static string ServerConnectionString =>
        Environment.GetEnvironmentVariable("BOLTWAY_TEST_POSTGRES")
        ?? "Host=127.0.0.1;Port=5432;Username=boltway;Password=boltway;Maximum Pool Size=20";

    /// <summary>
    /// The same server, on a database that already exists.
    /// </summary>
    /// <remarks>
    /// <c>CREATE DATABASE</c> and <c>DROP DATABASE</c> have to be issued from some other database,
    /// and <c>postgres</c> is the one every server has. <b>Setting it is not optional and leaving it
    /// out does not mean "the default":</b> Npgsql defaults the database to the <i>username</i>, so
    /// an unset one produced <c>3D000: database "boltway" does not exist</c>. That was a real
    /// bug twice in this file - once on the create, where it read as "no server is running", and
    /// once on the drop, where a <c>catch (NpgsqlException)</c> swallowed it and left 46 test
    /// databases behind across five green runs before anyone counted them. One property now, because
    /// two copies is how the second one stayed wrong.
    /// </remarks>
    private static string MaintenanceConnectionString =>
        new NpgsqlConnectionStringBuilder(ServerConnectionString) { Database = "postgres" }.ConnectionString;

    private readonly string _database =
        "ck_auth_test_" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);

    private readonly string _connectionString;

    private readonly List<ServiceProvider> _created = [];

    private readonly string _truncate;

    public PostgresDatabase()
    {
        _connectionString =
            new NpgsqlConnectionStringBuilder(ServerConnectionString) { Database = _database }.ConnectionString;

        try
        {
            Execute(MaintenanceConnectionString, $"CREATE DATABASE \"{_database}\";");
        }
        catch (Exception ex) when (ex is NpgsqlException or System.Net.Sockets.SocketException)
        {
            throw new InvalidOperationException(
                "This suite measures a real PostgreSQL server and has no meaningful result without one, "
                + "so it fails rather than skipping. Could not create a test database on '"
                + new NpgsqlConnectionStringBuilder(MaintenanceConnectionString) { Password = null }
                    .ConnectionString
                + "'. Start PostgreSQL, or set BOLTWAY_TEST_POSTGRES to a server where the login "
                + "may CREATE DATABASE.",
                ex);
        }

        // The migration, not EnsureCreated: what the contract runs against has to be what
        // `dotnet ef database update` produces at a deployment, or the suite validates a schema
        // nobody deploys.
        using (var provider = BuildProvider())
        using (var context = provider.GetRequiredService<IDbContextFactory<AuthDbContext>>().CreateDbContext())
        {
            context.Database.Migrate();
            _truncate = TruncateStatement(context);
        }
    }

    /// <summary>The connection string of this fixture's own database.</summary>
    public string ConnectionString => _connectionString;

    /// <summary>A service provider whose stores talk to an empty database.</summary>
    public IServiceProvider New()
    {
        Execute(_connectionString, _truncate);

        var provider = BuildProvider();
        _created.Add(provider);

        return provider;
    }

    public void Dispose()
    {
        foreach (var provider in _created)
        {
            provider.Dispose();
        }

        _created.Clear();

        // Pooled connections stay open after the providers are gone, and DROP DATABASE refuses while
        // any session is connected. ClearPool rather than ClearAllPools: the other test classes are
        // running in parallel against their own databases and share this process's pool table.
        using (var handle = new NpgsqlConnection(_connectionString))
        {
            NpgsqlConnection.ClearPool(handle);
        }

        // WITH (FORCE) terminates anything still attached. Without it a connection this fixture does
        // not know about - EF's, on a context a test leaked - leaves the database behind.
        //
        // NOT wrapped in a catch, deliberately, and the first draft was. "A leftover test database is
        // not worth failing a green run over" is true and it is also how this method spent five green
        // runs failing on every call: the connection string it used had no database name, Npgsql
        // defaulted it to the username, and the 3D000 went into the catch. IF EXISTS covers the only
        // benign failure there is; anything else is worth hearing about, and xUnit reports a fixture
        // that throws on disposal rather than hiding it.
        Execute(MaintenanceConnectionString, $"DROP DATABASE IF EXISTS \"{_database}\" WITH (FORCE);");
    }

    private ServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();

        // Through the extension a host would call, so the wiring is under test too rather than
        // hand-assembled here where a missing registration would never be noticed. In particular
        // IRelationalStoreBehavior is registered by that extension and nothing else supplies one, so
        // a version of it that forgot the line would fail here rather than racing in production.
        services.AddBoltwayPostgreSqlStores(_connectionString);

        return services.BuildServiceProvider();
    }

    /// <summary>Empty every table the model declares, in one statement.</summary>
    /// <remarks>
    /// One <c>TRUNCATE</c> naming all of them, rather than a <c>DELETE</c> each: PostgreSQL refuses
    /// to truncate a table another table references unless that table is in the same statement, so
    /// listing all of them is what makes the <c>external_logins</c> → <c>users</c> foreign key a
    /// non-issue. <c>CASCADE</c> is deliberately <i>not</i> used - with it, a table outside this
    /// model that referenced one of these would be silently emptied too; without it, that situation
    /// fails the statement and says so.
    /// </remarks>
    private static string TruncateStatement(AuthDbContext context)
    {
        var tables = context.Model.GetEntityTypes()
            .Select(entity => entity.GetTableName())
            .Where(name => name is not null)
            .Select(name => "\"" + name!.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"")
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal);

        return "TRUNCATE " + string.Join(", ", tables) + ";";
    }

    private static void Execute(string connectionString, string sql)
    {
        using var connection = new NpgsqlConnection(connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
}
