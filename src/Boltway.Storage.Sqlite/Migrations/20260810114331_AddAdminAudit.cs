// The administrative audit log.
//
// A surrogate key, unlike every other table here: the natural key would be (time, actor, target),
// and two actions in the same tick against the same account are a real sequence rather than a
// collision. An append-only table is the one place a duplicate has to be storable.
//
// No foreign key to users. An entry must outlive the account it describes — that is most of the
// point of anonymisation keeping the subject row, and all of the point of recording an action
// against a handle that resolved to nobody.
//
// Two indexes, for the two questions it is read with: "what happened lately" and "what has been
// done to this account". Neither survives a scan once the table is a year old, and an audit log is
// the one table nobody prunes.

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Boltway.Storage.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddAdminAudit : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "admin_audit",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    at = table.Column<long>(type: "INTEGER", nullable: false),
                    actor_kind = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    actor_subject = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    actor_client = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    action = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    target_realm = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    target_subject = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    target_handle = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    outcome = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    detail = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    correlation_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_admin_audit", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_admin_audit_at",
                table: "admin_audit",
                column: "at");

            migrationBuilder.CreateIndex(
                name: "ix_admin_audit_target_at",
                table: "admin_audit",
                columns: new[] { "target_subject", "at" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "admin_audit");
        }
    }
}
