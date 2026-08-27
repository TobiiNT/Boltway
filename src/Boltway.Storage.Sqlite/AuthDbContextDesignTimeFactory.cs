using Boltway.Storage.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Boltway.Storage.Sqlite;

/// <summary>
/// Lets <c>dotnet ef</c> build the model without a host.
/// </summary>
/// <remarks>
/// <para>
/// The tools' fallback is to find a <c>Program.cs</c> and run the host's DI to obtain a context.
/// This package has no host, so without this class every <c>dotnet ef migrations add</c> would need
/// a startup project pointed at some sample server, and the migration a maintainer generated would
/// depend on that server's configuration rather than on this package's model.
/// </para>
/// <para>
/// <b>The connection string here is never opened.</b> Generating a migration reads the model, not
/// the database. It is a filename so that a mistake - running <c>database update</c> with this
/// factory - creates a stray file in the working directory rather than touching a real database.
/// </para>
/// </remarks>
public sealed class AuthDbContextDesignTimeFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    /// <summary>Build a context for the tools.</summary>
    /// <param name="args">Arguments from the tools. Unused.</param>
    /// <returns>A context configured for SQLite.</returns>
    public AuthDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseSqlite(
                "Data Source=boltway-auth-design-time.db",
                sqlite => sqlite.MigrationsAssembly(typeof(AuthDbContextDesignTimeFactory).Assembly.FullName))
            .Options;

        return new AuthDbContext(options);
    }
}
