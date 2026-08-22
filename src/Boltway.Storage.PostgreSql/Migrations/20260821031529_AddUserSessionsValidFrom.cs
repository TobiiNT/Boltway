using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Boltway.Storage.PostgreSql.Migrations
{
    /// <inheritdoc />
    public partial class AddUserSessionsValidFrom : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "sessions_valid_from",
                table: "users",
                type: "bigint",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "sessions_valid_from",
                table: "users");
        }
    }
}
