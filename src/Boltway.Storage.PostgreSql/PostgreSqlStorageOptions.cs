namespace Boltway.Storage.PostgreSql;

/// <summary>
/// What <c>AddBoltwayPostgreSqlStores</c> does to the connection string before Npgsql reads it.
/// </summary>
/// <remarks>
/// Read once, during that call. Nothing here is registered in the container, so changing an instance
/// afterwards changes nothing.
/// </remarks>
public sealed class PostgreSqlStorageOptions
{
    /// <summary>
    /// Whether a connection string naming no GSS encryption mode reaches Npgsql with
    /// <c>GSS Encryption Mode=Disable</c>. <see langword="true"/> unless set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why the default is not Npgsql's.</b> Npgsql's own default is <c>Prefer</c>, so every
    /// physical connection over TCP first tries to negotiate GSS encryption, and that loads the
    /// Kerberos GSSAPI library - <c>libgssapi_krb5.so.2</c> on Linux. A host without one, a slim
    /// container image for instance, gets <c>Cannot load library libgssapi_krb5.so.2</c> on
    /// standard error from the .NET runtime and then connects without GSS encryption. Nothing
    /// fails, and that is why it survives: the line reads as an error in a deploy log and is not one,
    /// and every connection still pays for the attempt. A deployment that does not authenticate to
    /// its database with Kerberos gains nothing from it.
    /// </para>
    /// <para>
    /// Measured 2026-09-26 on Npgsql 10.0.3 and the .NET 10.0.12 runtime on glibc, against
    /// PostgreSQL 16 over TCP, with the library made unloadable: five physical connections printed
    /// the line once and threw and caught a <c>TypeInitializationException</c> on every one of them,
    /// and all five connected. With <c>Disable</c>, neither happened. Not measured on a musl-based
    /// image.
    /// </para>
    /// <para>
    /// <b>What a deployment named wins, and so does what it exported.</b> The mode is filled in only
    /// where Npgsql would otherwise fall back to its own built-in default. A mode the connection
    /// string names, under any spelling Npgsql accepts, is kept and the string is passed on exactly
    /// as written. So is a mode in <c>PGGSSENCMODE</c>, which Npgsql reads before that default, and
    /// which is read here with the same parse Npgsql uses, so a value Npgsql would ignore is treated
    /// as absent. Overriding either would switch off GSS encryption somebody asked for, and a
    /// transport setting must never fail quietly in that direction. The environment is read during
    /// the registration call, not per connection.
    /// </para>
    /// <para>
    /// <b>Who should set this to <see langword="false"/>, or name the mode instead.</b> A deployment
    /// whose database expects GSS encryption and that relied on <c>Prefer</c> negotiating it without
    /// being asked: with this on, it no longer does. Naming the mode is the better fix, and
    /// <c>Require</c> rather than <c>Prefer</c> if the encryption is what protects the connection,
    /// because <c>Prefer</c> carries on without it when it cannot be negotiated. Setting this to
    /// <see langword="false"/> passes the connection string to Npgsql untouched and unparsed.
    /// </para>
    /// </remarks>
    public bool DisableGssEncryptionByDefault { get; set; } = true;
}
