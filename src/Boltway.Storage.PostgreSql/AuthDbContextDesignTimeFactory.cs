using Boltway.Storage.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Boltway.Storage.PostgreSql;

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
/// the database. It names a database that does not exist and a host that is not a deployment's, so a
/// mistake — running <c>database update</c> with this factory — fails to connect rather than
/// touching a real database. That is a weaker guard than the SQLite factory's, which can only ever
/// create a stray file: a local PostgreSQL listening on the default port is a real thing to hit.
/// Hence the name.
/// </para>
/// </remarks>
public sealed class AuthDbContextDesignTimeFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    /// <summary>Build a context for the tools.</summary>
    /// <param name="args">Arguments from the tools. Unused.</param>
    /// <returns>A context configured for PostgreSQL.</returns>
    public AuthDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseNpgsql(
                "Host=localhost;Database=boltway-auth-design-time-do-not-use;Username=design-time",
                npgsql => npgsql.MigrationsAssembly(typeof(AuthDbContextDesignTimeFactory).Assembly.FullName))
            .Options;

        return new AuthDbContext(options);
    }
}
