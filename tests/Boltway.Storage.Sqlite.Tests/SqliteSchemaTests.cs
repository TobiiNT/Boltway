using Boltway.Storage.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.Storage.Sqlite.Tests;

/// <summary>
/// What the migration produced, checked against the model and against the database.
/// </summary>
public sealed class SqliteSchemaTests : IDisposable
{
    private readonly SqliteDatabases _databases = new();

    [Fact]
    public void The_migration_leaves_nothing_pending()
    {
        // A migration that does not match the model is a deployment where `dotnet ef database
        // update` succeeds and the first query fails. It is also the only thing standing between the
        // contract suite and a schema created by EnsureCreated, which is not what a deployment runs.
        using var context = NewContext();

        Assert.Empty(context.Database.GetPendingMigrations());
        Assert.NotEmpty(context.Database.GetAppliedMigrations());
    }

    [Fact]
    public void No_column_is_named_for_a_secret_rather_than_a_digest()
    {
        // The property the whole design is for, asked of the schema rather than of the code. A
        // column called `token`, `code`, `secret` or `refresh_token` would be where a later change
        // puts the plaintext, and Sha256Hash exists so there is nothing to put there.
        using var context = NewContext();

        var columns = AllColumns(context);

        Assert.NotEmpty(columns);

        var suspicious = columns
            .Where(c => c.Column is "token" or "code" or "secret" or "password" or "refresh_token" or "access_token")
            .ToList();

        Assert.True(
            suspicious.Count == 0,
            "A column is named for a secret rather than for a digest of one: "
            + string.Join(", ", suspicious.Select(c => $"{c.Table}.{c.Column}")));

        // And the two that hold credentials are what they say they are: BLOB digests, and a column
        // whose name says it holds a hash.
        Assert.Contains(("authorization_codes", "code_hash"), columns);
        Assert.Contains(("refresh_tokens", "token_hash"), columns);
        Assert.Contains(("users", "password_hash"), columns);
    }

    [Fact]
    public void The_connection_enforces_foreign_keys()
    {
        // SQLite ignores REFERENCES clauses unless foreign_keys is on, and it is off by default -
        // per connection, not per database. EF Core's SQLite provider turns it on when it opens a
        // connection, which is a property of a library this project does not own, so it is measured
        // here rather than asserted in a comment. Without it the external_logins foreign key in the
        // migration is decoration.
        using var context = NewContext();

        context.Database.OpenConnection();

        using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = "PRAGMA foreign_keys;";

        Assert.Equal(1L, Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture));
    }

    private AuthDbContext NewContext() =>
        _databases.New().GetRequiredService<IDbContextFactory<AuthDbContext>>().CreateDbContext();

    private static List<(string Table, string Column)> AllColumns(AuthDbContext context)
    {
        var columns = new List<(string, string)>();

        context.Database.OpenConnection();

        using var command = context.Database.GetDbConnection().CreateCommand();

        // sqlite_schema, not the EF model: the question is what the migration actually created.
        command.CommandText =
            "SELECT m.name, p.name FROM sqlite_schema m JOIN pragma_table_info(m.name) p "
            + "WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%';";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            columns.Add((reader.GetString(0), reader.GetString(1)));
        }

        return columns;
    }

    public void Dispose() => _databases.Dispose();
}
