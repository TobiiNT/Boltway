using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Boltway.Storage.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddClientAssertions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "client_assertions",
                columns: table => new
                {
                    client_id = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    jwt_id = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_client_assertions", x => new { x.client_id, x.jwt_id });
                });

            migrationBuilder.CreateIndex(
                name: "ix_client_assertions_expires_at",
                table: "client_assertions",
                column: "expires_at");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "client_assertions");
        }
    }
}
