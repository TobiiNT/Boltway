using Boltway.Storage.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Boltway.Storage.PostgreSql.Tests;

/// <summary>
/// GSS encryption is off unless a deployment names it, and whatever a deployment names wins.
/// </summary>
/// <remarks>
/// <para>
/// <b>No server, and not because one would be inconvenient.</b> What these read is the connection
/// string the registered context hands Npgsql: with nothing configured that needs a data source,
/// the EF provider opens <c>new NpgsqlConnection(ConnectionString)</c> with exactly this string,
/// and whether Npgsql tries GSS encryption is decided from what it names, not from anything the
/// server says. Opening a connection would measure the server's answer instead of that decision.
/// </para>
/// <para>
/// <b>Alone, in a collection that runs after every other.</b> Npgsql also reads
/// <c>PGGSSENCMODE</c>, so each test here sets or clears it, and it is one value for the whole
/// process: set beside the contract suite, it would change what that suite's connections do while
/// they run. Every test starts with it cleared and puts back what the process had.
/// </para>
/// </remarks>
[Collection(ChangesTheProcessEnvironment.Name)]
public sealed class PostgreSqlGssEncryptionTests : IDisposable
{
    private const string Variable = "PGGSSENCMODE";

    /// <summary>A string a deployment might write, naming no GSS encryption mode.</summary>
    private const string Unnamed =
        "Host=db.example.test;Port=5433;Database=auth;Username=auth;SSL Mode=Require;Maximum Pool Size=7";

    private readonly string? _exported = Environment.GetEnvironmentVariable(Variable);

    public PostgreSqlGssEncryptionTests() => Environment.SetEnvironmentVariable(Variable, null);

    public void Dispose() => Environment.SetEnvironmentVariable(Variable, _exported);

    [Fact]
    public void A_connection_string_naming_no_mode_is_opened_with_gss_encryption_disabled()
    {
        // Disable, read back, is proof the string names it: Npgsql's property reports its own
        // default, Prefer, for a string that names nothing.
        Assert.Equal(GssEncryptionMode.Disable, ModeIn(Registered(services =>
            services.AddBoltwayPostgreSqlStores(Unnamed))));

        Assert.Equal(GssEncryptionMode.Disable, ModeIn(Registered(services =>
            services.AddBoltwayPostgreSqlStores(Unnamed, _ => { }))));
    }

    [Fact]
    public void Filling_in_the_mode_changes_nothing_else_in_the_string()
    {
        // The string is parsed and written back out to add one key. Anything else that moved on
        // that trip - a dropped key, a changed value - would be a different connection.
        var effective = new NpgsqlConnectionStringBuilder(Registered(services =>
            services.AddBoltwayPostgreSqlStores(Unnamed)));

        Assert.True(
            effective.Remove(nameof(NpgsqlConnectionStringBuilder.GssEncryptionMode)),
            $"No GSS encryption mode was added: {effective.ConnectionString}");

        Assert.True(
            effective.EquivalentTo(new NpgsqlConnectionStringBuilder(Unnamed)),
            $"Something besides the mode changed: {effective.ConnectionString}");
    }

    [Theory]
    [InlineData("GSS Encryption Mode=Prefer")]
    [InlineData("gss encryption mode=Require")]
    [InlineData("GssEncryptionMode=Prefer")]
    [InlineData("GSSENCRYPTIONMODE=disable")]
    public void A_mode_the_connection_string_names_is_passed_on_exactly_as_written(string named)
    {
        // Every spelling Npgsql accepts for the key, because a check that knew only one would add
        // a second mode beside a deployment's own, and which of two Npgsql honours is not a thing
        // a deployment should have to know. Prefer is here on purpose: it is Npgsql's default,
        // and a deployment that wrote it down chose it.
        var written = "Host=db.example.test;Database=auth;" + named;

        Assert.Equal(written, Registered(services => services.AddBoltwayPostgreSqlStores(written)));
    }

    [Theory]
    [InlineData("prefer")]
    [InlineData("Require")]
    [InlineData("DISABLE")]
    public void A_mode_PGGSSENCMODE_names_is_left_for_npgsql_to_read(string exported)
    {
        // Npgsql reads the variable only when the string names nothing, so a mode written into the
        // string here would silently outrank it - Require included.
        Environment.SetEnvironmentVariable(Variable, exported);

        Assert.Equal(Unnamed, Registered(services => services.AddBoltwayPostgreSqlStores(Unnamed)));
    }

    [Fact]
    public void A_PGGSSENCMODE_value_npgsql_would_ignore_is_treated_as_absent()
    {
        // Npgsql parses the variable and falls back to its own default when that fails, so a value
        // it cannot parse chose nothing. Replacing that default is the whole of this rule.
        Environment.SetEnvironmentVariable(Variable, "on");

        Assert.Equal(GssEncryptionMode.Disable, ModeIn(Registered(services =>
            services.AddBoltwayPostgreSqlStores(Unnamed))));
    }

    [Fact]
    public void Turned_off_the_connection_string_reaches_npgsql_as_written()
    {
        var effective = Registered(services =>
            services.AddBoltwayPostgreSqlStores(Unnamed, storage => storage.DisableGssEncryptionByDefault = false));

        Assert.Equal(Unnamed, effective);

        // Which is Npgsql's own default back again, and that is what turning it off is for.
        Assert.Equal(GssEncryptionMode.Prefer, ModeIn(effective));
    }

    [Fact]
    public void A_connection_string_npgsql_cannot_parse_is_refused_by_the_registration()
    {
        // `gssencmode` is libpq's keyword for this setting and Npgsql does not accept it, so a
        // string copied from a libpq deployment is the likely way to meet this.
        const string Libpq = "Host=db.example.test;Database=auth;gssencmode=disable";

        var refused = Assert.Throws<ArgumentException>(() =>
            new ServiceCollection().AddBoltwayPostgreSqlStores(Libpq));

        Assert.Contains("gssencmode", refused.Message, StringComparison.Ordinal);

        // The control: with nothing filled in, nothing is parsed here, and the string waits for the
        // first connection exactly as it did before this rule existed.
        Assert.Equal(Libpq, Registered(services =>
            services.AddBoltwayPostgreSqlStores(Libpq, storage => storage.DisableGssEncryptionByDefault = false)));
    }

    /// <summary>The connection string the registered stores' context hands Npgsql.</summary>
    private static string Registered(Action<IServiceCollection> register)
    {
        var services = new ServiceCollection();
        register(services);

        using var provider = services.BuildServiceProvider();
        using var context = provider.GetRequiredService<IDbContextFactory<AuthDbContext>>().CreateDbContext();

        return context.Database.GetConnectionString()
            ?? throw new InvalidOperationException("The registered context carries no connection string.");
    }

    private static GssEncryptionMode ModeIn(string connectionString) =>
        new NpgsqlConnectionStringBuilder(connectionString).GssEncryptionMode;
}

/// <summary>
/// Tests that change the process environment, run on their own after every other collection.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ChangesTheProcessEnvironment
{
    /// <summary>The collection's name, as the test classes in it cite it.</summary>
    public const string Name = "Process environment";
}
