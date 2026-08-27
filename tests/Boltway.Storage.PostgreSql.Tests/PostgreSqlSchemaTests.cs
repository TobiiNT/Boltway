using Boltway.Storage.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Boltway.Storage.PostgreSql.Tests;

/// <summary>
/// What the migration produced, asked of <c>information_schema</c> rather than of the model.
/// </summary>
/// <remarks>
/// The PostgreSQL counterpart of <c>SqliteSchemaTests</c>. Two of these have no SQLite twin, because
/// they pin decisions where this provider could plausibly have diverged and deliberately did not -
/// <c>bytea</c> for digests and <c>bigint</c> for instants - and one replaces a SQLite test that has
/// no meaning here: SQLite ignores <c>REFERENCES</c> unless a per-connection pragma is set, so the
/// SQLite suite reads the pragma back; PostgreSQL always enforces one, so the equivalent measurement
/// is to break it and watch the server refuse.
/// </remarks>
public sealed class PostgreSqlSchemaTests(PostgresDatabase database) : IClassFixture<PostgresDatabase>
{
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
        var columns = AllColumns();

        Assert.NotEmpty(columns);

        var suspicious = columns
            .Where(c => c.Column is "token" or "code" or "secret" or "password" or "refresh_token" or "access_token")
            .ToList();

        Assert.True(
            suspicious.Count == 0,
            "A column is named for a secret rather than for a digest of one: "
            + string.Join(", ", suspicious.Select(c => $"{c.Table}.{c.Column}")));

        Assert.Contains(("authorization_codes", "code_hash"), columns.Select(c => (c.Table, c.Column)));
        Assert.Contains(("refresh_tokens", "token_hash"), columns.Select(c => (c.Table, c.Column)));
        Assert.Contains(("users", "password_hash"), columns.Select(c => (c.Table, c.Column)));
    }

    [Fact]
    public void A_digest_column_is_bytea_and_an_instant_column_is_bigint()
    {
        // The two places PostgreSQL offers something SQLite does not, and both offers are declined.
        //
        // `bytea` rather than a hex or base64 `text`: a digest compared as text is compared under a
        // collation, and the primary key of the two tables replay protection depends on is not a
        // place to introduce a collation. bytea has neither a collation nor a length limit, which is
        // why HasMaxLength(32) leaves no trace here - the 32 bytes are guaranteed by Sha256Hash,
        // which cannot produce another length, and re-checked by StoredValues.ToHash on the way back.
        //
        // `bigint` UTC ticks rather than `timestamptz`, which is the type a PostgreSQL schema would
        // normally use. timestamptz holds microseconds and a .NET tick is 100 ns, so the round trip
        // is lossy - measured through Npgsql against this server rather than reasoned about: 200
        // values of DateTimeOffset.UtcNow written to a timestamptz column and read back came out
        // bit-identical 18 times, and written to a bigint of UtcTicks, 200 times.
        // ConsentStoreContract's `Assert.Equal(now, found.GrantedAt)` compares exactly that, so a
        // timestamptz column would fail the shared contract about nine runs in ten. The cost of
        // ticks is that a DBA reading the table sees a large integer; the SQLite provider pays the
        // same price for a different reason, and paying it identically is what keeps one migration
        // history readable against two.
        var types = AllColumns().ToDictionary(c => (c.Table, c.Column), c => c.DataType);

        Assert.Equal("bytea", types[("authorization_codes", "code_hash")]);
        Assert.Equal("bytea", types[("refresh_tokens", "token_hash")]);
        Assert.Equal("bytea", types[("refresh_tokens", "predecessor_hash")]);
        Assert.Equal("bytea", types[("refresh_tokens", "successor_hash")]);

        Assert.Equal("bigint", types[("authorization_codes", "expires_at")]);
        Assert.Equal("bigint", types[("authorization_codes", "redeemed_at")]);
        Assert.Equal("bigint", types[("refresh_tokens", "consumed_at")]);
        Assert.Equal("bigint", types[("consents", "granted_at")]);
        Assert.Equal("bigint", types[("grants", "revoked_at")]);
        Assert.Equal("bigint", types[("users", "disabled_at")]);

        // And not one of them is a timestamp of any kind, so this cannot be satisfied by a schema
        // where somebody converted half of them.
        Assert.DoesNotContain(types.Values, type => type.StartsWith("timestamp", StringComparison.Ordinal));
    }

    [Fact]
    public void The_database_refuses_a_link_to_an_account_that_does_not_exist()
    {
        // The SQLite suite reads `PRAGMA foreign_keys` back because SQLite ignores REFERENCES
        // clauses unless it is on. PostgreSQL has no such switch, so the question worth asking here
        // is not whether enforcement is enabled but whether the constraint reached the database at
        // all - which is checked by breaking it, from raw SQL, underneath the store that has its own
        // check for the same thing.
        var exception = Assert.Throws<PostgresException>(() => Execute(
            "INSERT INTO external_logins (upstream_issuer, upstream_subject, subject) "
            + "VALUES ('https://accounts.google.com', 'g-1', '01J8XKQ7M3N4P5R6S7T8V9W0ZZ');"));

        Assert.Equal(PostgresErrorCodes.ForeignKeyViolation, exception.SqlState);
    }

    [Fact]
    public void String_equality_in_this_database_is_byte_wise()
    {
        // EfUserStore folds case in C# and compares the folded value in SQL, on the stated grounds
        // that this "makes the answer the same on every provider". On PostgreSQL that sentence holds
        // only while the column's collation is deterministic: under a non-deterministic ICU
        // collation `=` folds case itself, and UserStoreContract's
        // An_upstream_subject_is_matched_ordinally - which requires 'abcDEF' and 'ABCdef' to be two
        // different upstream identities - would be false of the database rather than of the code.
        //
        // A property of the database a deployment creates, not of anything this package ships, so it
        // is measured rather than assumed. A deployment that creates its database with
        // `deterministic = false` fails here and should.
        Assert.False(Scalar<bool>("SELECT 'abcDEF' = 'ABCdef';"));
        Assert.True(Scalar<bool>("SELECT 'abcDEF' = 'abcDEF';"));
    }

    private AuthDbContext NewContext() =>
        database.New().GetRequiredService<IDbContextFactory<AuthDbContext>>().CreateDbContext();

    private List<(string Table, string Column, string DataType)> AllColumns()
    {
        var columns = new List<(string, string, string)>();

        using var connection = new NpgsqlConnection(database.ConnectionString);
        connection.Open();

        using var command = connection.CreateCommand();

        // information_schema, not the EF model: the question is what the migration actually created.
        command.CommandText =
            "SELECT table_name, column_name, data_type FROM information_schema.columns "
            + "WHERE table_schema = 'public' ORDER BY table_name, column_name;";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            columns.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2)));
        }

        return columns;
    }

    private void Execute(string sql)
    {
        using var connection = new NpgsqlConnection(database.ConnectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private T Scalar<T>(string sql)
    {
        using var connection = new NpgsqlConnection(database.ConnectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = sql;

        return (T)command.ExecuteScalar()!;
    }
}
