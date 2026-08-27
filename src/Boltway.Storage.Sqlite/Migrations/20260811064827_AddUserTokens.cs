// The one-time links behind the email flows. S-47.
//
// The hash is the primary key, and the plaintext is never stored - N-16, the same rule the
// authorization codes and refresh tokens follow. A stolen backup is then a list of digests rather
// than a set of live links into every account.
//
// No foreign key to users, and for a narrower reason than admin_audit's: anonymising an account
// must not fail because a reset link was outstanding. The operation destroys the link; the database
// is not asked to.
//
// Two indexes. (subject, purpose) is S-47's bulk delete, which runs on every password change by any
// route and is therefore on a request path - without it that is a scan of every live link in the
// deployment each time anybody changes a password. expires_at is the sweeper's, on the same
// reasoning the codes table records: housekeeping that scans is housekeeping that gets turned off.

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Boltway.Storage.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddUserTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "user_tokens",
                columns: table => new
                {
                    token_hash = table.Column<byte[]>(type: "BLOB", maxLength: 32, nullable: false),
                    subject = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    purpose = table.Column<int>(type: "INTEGER", nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    detail = table.Column<string>(type: "TEXT", maxLength: 320, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_tokens", x => x.token_hash);
                });

            migrationBuilder.CreateIndex(
                name: "ix_user_tokens_expires_at",
                table: "user_tokens",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "ix_user_tokens_subject_purpose",
                table: "user_tokens",
                columns: new[] { "subject", "purpose" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "user_tokens");
        }
    }
}
