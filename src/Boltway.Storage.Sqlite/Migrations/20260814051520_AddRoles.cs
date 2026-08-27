using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Boltway.Storage.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddRoles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "roles",
                columns: table => new
                {
                    realm = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false, defaultValue: "default"),
                    id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    name = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    permissions = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_roles", x => new { x.realm, x.id });
                });

            migrationBuilder.CreateTable(
                name: "user_roles",
                columns: table => new
                {
                    subject = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    role_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    realm = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false, defaultValue: "default")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_roles", x => new { x.subject, x.role_id });
                    table.ForeignKey(
                        name: "FK_user_roles_roles_realm_role_id",
                        columns: x => new { x.realm, x.role_id },
                        principalTable: "roles",
                        principalColumns: new[] { "realm", "id" },
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_user_roles_users_subject",
                        column: x => x.subject,
                        principalTable: "users",
                        principalColumn: "subject",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_user_roles_realm_role_id",
                table: "user_roles",
                columns: new[] { "realm", "role_id" });

            // Backfill before the drop, and this is the whole reason this migration is not what
            // `ef migrations add` produced. It scaffolded DropColumn first, which is a silent
            // deletion of every account's role: the column goes, the join table is empty, and the
            // next token every person is issued carries nothing. EF said so - "an operation was
            // scaffolded that may result in the loss of data" - and that warning is the only thing
            // standing between a scaffold and a directory that has forgotten who its administrators are.
            //
            // A role row per distinct value already in use, id and name both that value. Permissions
            // are empty on purpose: this library has never known what a role means, so it cannot
            // invent what one stood for. A resource server reading these gets ids it recognises and
            // no permissions claim, which is exactly the state it was in before this migration -
            // the resource server's own table is what resolved them, and still does until somebody writes
            // permissions here.
            migrationBuilder.Sql(
                """
                INSERT INTO roles (realm, id, name, permissions)
                SELECT DISTINCT realm, role, role, ''
                FROM users
                WHERE role IS NOT NULL AND role <> ''
                """);

            migrationBuilder.Sql(
                """
                INSERT INTO user_roles (subject, realm, role_id)
                SELECT subject, realm, role
                FROM users
                WHERE role IS NOT NULL AND role <> ''
                """);

            migrationBuilder.DropColumn(
                name: "role",
                table: "users");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "role",
                table: "users",
                type: "TEXT",
                maxLength: 64,
                nullable: true);
            // Backfilled before the tables go, for the reason `Up` gives from the other side. The
            // scaffold added an empty column and dropped the rows that could have filled it, which
            // makes a rollback a wipe.
            //
            // One role per account, the lowest id, because the column holds one. An account holding
            // several loses the rest - a real loss this direction cannot avoid, and the reason a
            // rollback past this migration is not free.
            migrationBuilder.Sql(
                """
                UPDATE users
                SET role = (
                    SELECT MIN(user_roles.role_id)
                    FROM user_roles
                    WHERE user_roles.subject = users.subject)
                """);

            migrationBuilder.DropTable(
                name: "user_roles");

            migrationBuilder.DropTable(
                name: "roles");
        }
    }
}
