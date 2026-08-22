using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Boltway.Storage.PostgreSql.Migrations
{
    /// <inheritdoc />
    public partial class AddClients : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "clients",
                columns: table => new
                {
                    client_id = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    client_id_kind = table.Column<int>(type: "integer", nullable: false),
                    name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    secret_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: true),
                    owner = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    scopes = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    redirect_uris = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    disabled_at = table.Column<long>(type: "bigint", nullable: true),
                    created_at = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_clients", x => x.client_id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_clients_owner",
                table: "clients",
                column: "owner");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "clients");
        }
    }
}
