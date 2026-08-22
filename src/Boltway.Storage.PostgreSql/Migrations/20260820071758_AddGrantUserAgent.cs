using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Boltway.Storage.PostgreSql.Migrations
{
    /// <inheritdoc />
    public partial class AddGrantUserAgent : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "user_agent",
                table: "grants",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "user_agent",
                table: "grants");
        }
    }
}
