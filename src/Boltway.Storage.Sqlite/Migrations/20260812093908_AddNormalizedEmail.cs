using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Boltway.Storage.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddNormalizedEmail : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "normalized_email",
                table: "users",
                type: "TEXT",
                maxLength: 320,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "ix_users_realm_normalized_email",
                table: "users",
                columns: new[] { "realm", "normalized_email" });

            // The column is useless without this. Every account that already exists has an address
            // in `email` and nothing in `normalized_email`, so without a backfill this migration
            // ships an index over nulls and sign-in by address works only for accounts whose email
            // is written again afterwards - which is no account anybody has, and a failure that
            // looks exactly like the feature not existing.
            //
            // SQL UPPER rather than the C# fold, because a migration has no C#. They agree on
            // ASCII, which is every address in practice; one that disagrees simply does not match
            // until its address is next set, which is a row that cannot sign in by address rather
            // than a row that signs in as somebody else.
            migrationBuilder.Sql(
                "UPDATE users SET normalized_email = UPPER(email) WHERE email IS NOT NULL;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_users_realm_normalized_email",
                table: "users");

            migrationBuilder.DropColumn(
                name: "normalized_email",
                table: "users");
        }
    }
}
