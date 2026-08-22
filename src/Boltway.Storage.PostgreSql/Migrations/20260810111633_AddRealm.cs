// Realms, added before anybody has two.
//
// The column arrives with a default of "default", so every existing row is in the default realm and
// no backfill runs. That is the whole reason to do it now: a realm column added after a directory
// is populated is a migration across every deployed database, executed against tables holding live
// credentials, by somebody who has just discovered they need it.
//
// The username index becomes (realm, normalized_username) and the external-login key becomes
// (realm, upstream_issuer, upstream_subject). A realm column that exists and is not part of those
// keys reads as tenancy and is not — two realms would be unable to hold the same username, which is
// the one thing having realms is for.
//
// Nothing is scoped by realm that is keyed on a subject: subjects are ULIDs and unique everywhere,
// so grants, consents and refresh families are already isolated and a second mechanism would only
// be a second thing to disagree.

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Boltway.Storage.PostgreSql.Migrations
{
    /// <inheritdoc />
    public partial class AddRealm : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ux_users_normalized_username",
                table: "users");

            migrationBuilder.DropPrimaryKey(
                name: "PK_external_logins",
                table: "external_logins");

            migrationBuilder.AddColumn<string>(
                name: "realm",
                table: "users",
                type: "character varying(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "default");

            migrationBuilder.AddColumn<string>(
                name: "realm",
                table: "external_logins",
                type: "character varying(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "default");

            migrationBuilder.AddPrimaryKey(
                name: "PK_external_logins",
                table: "external_logins",
                columns: new[] { "realm", "upstream_issuer", "upstream_subject" });

            migrationBuilder.CreateIndex(
                name: "ux_users_realm_normalized_username",
                table: "users",
                columns: new[] { "realm", "normalized_username" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ux_users_realm_normalized_username",
                table: "users");

            migrationBuilder.DropPrimaryKey(
                name: "PK_external_logins",
                table: "external_logins");

            migrationBuilder.DropColumn(
                name: "realm",
                table: "users");

            migrationBuilder.DropColumn(
                name: "realm",
                table: "external_logins");

            migrationBuilder.AddPrimaryKey(
                name: "PK_external_logins",
                table: "external_logins",
                columns: new[] { "upstream_issuer", "upstream_subject" });

            migrationBuilder.CreateIndex(
                name: "ux_users_normalized_username",
                table: "users",
                column: "normalized_username",
                unique: true);
        }
    }
}
