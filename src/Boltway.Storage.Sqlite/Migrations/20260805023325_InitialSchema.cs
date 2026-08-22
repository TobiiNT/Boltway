using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Boltway.Storage.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class InitialSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "authorization_codes",
                columns: table => new
                {
                    code_hash = table.Column<byte[]>(type: "BLOB", maxLength: 32, nullable: false),
                    grant_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    client_id = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    client_id_kind = table.Column<int>(type: "INTEGER", nullable: false),
                    redirect_uri_used = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    code_challenge = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    challenge_method = table.Column<int>(type: "INTEGER", nullable: false),
                    pkce_was_requested = table.Column<bool>(type: "INTEGER", nullable: false),
                    scope = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    resources = table.Column<string>(type: "TEXT", maxLength: 4096, nullable: false),
                    nonce = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    auth_time = table.Column<long>(type: "INTEGER", nullable: false),
                    issued_at = table.Column<long>(type: "INTEGER", nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    redeemed_at = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_authorization_codes", x => x.code_hash);
                });

            migrationBuilder.CreateTable(
                name: "consents",
                columns: table => new
                {
                    subject = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    client_id = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    client_id_kind = table.Column<int>(type: "INTEGER", nullable: false),
                    scope = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    resources = table.Column<string>(type: "TEXT", maxLength: 4096, nullable: false),
                    granted_at = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_consents", x => new { x.subject, x.client_id });
                });

            migrationBuilder.CreateTable(
                name: "grants",
                columns: table => new
                {
                    grant_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    subject = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    client_id = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    client_id_kind = table.Column<int>(type: "INTEGER", nullable: false),
                    scope = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    resources = table.Column<string>(type: "TEXT", maxLength: 4096, nullable: false),
                    created_at = table.Column<long>(type: "INTEGER", nullable: false),
                    auth_time = table.Column<long>(type: "INTEGER", nullable: false),
                    revoked_at = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_grants", x => x.grant_id);
                });

            migrationBuilder.CreateTable(
                name: "refresh_token_families",
                columns: table => new
                {
                    family_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    revoked_at = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_refresh_token_families", x => x.family_id);
                });

            migrationBuilder.CreateTable(
                name: "refresh_tokens",
                columns: table => new
                {
                    token_hash = table.Column<byte[]>(type: "BLOB", maxLength: 32, nullable: false),
                    grant_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    family_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    generation = table.Column<int>(type: "INTEGER", nullable: false),
                    predecessor_hash = table.Column<byte[]>(type: "BLOB", maxLength: 32, nullable: true),
                    successor_hash = table.Column<byte[]>(type: "BLOB", maxLength: 32, nullable: true),
                    issued_at = table.Column<long>(type: "INTEGER", nullable: false),
                    expires_at = table.Column<long>(type: "INTEGER", nullable: false),
                    consumed_at = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_refresh_tokens", x => x.token_hash);
                });

            migrationBuilder.CreateTable(
                name: "users",
                columns: table => new
                {
                    subject = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    username = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    normalized_username = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    email = table.Column<string>(type: "TEXT", maxLength: 320, nullable: true),
                    email_verified = table.Column<bool>(type: "INTEGER", nullable: false),
                    password_hash = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    disabled_at = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_users", x => x.subject);
                });

            migrationBuilder.CreateTable(
                name: "external_logins",
                columns: table => new
                {
                    upstream_issuer = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    upstream_subject = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    subject = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_external_logins", x => new { x.upstream_issuer, x.upstream_subject });
                    table.ForeignKey(
                        name: "FK_external_logins_users_subject",
                        column: x => x.subject,
                        principalTable: "users",
                        principalColumn: "subject",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_authorization_codes_expires_at",
                table: "authorization_codes",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "ix_external_logins_subject",
                table: "external_logins",
                column: "subject");

            migrationBuilder.CreateIndex(
                name: "ix_refresh_tokens_family_id",
                table: "refresh_tokens",
                column: "family_id");

            migrationBuilder.CreateIndex(
                name: "ux_users_normalized_username",
                table: "users",
                column: "normalized_username",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "authorization_codes");

            migrationBuilder.DropTable(
                name: "consents");

            migrationBuilder.DropTable(
                name: "external_logins");

            migrationBuilder.DropTable(
                name: "grants");

            migrationBuilder.DropTable(
                name: "refresh_token_families");

            migrationBuilder.DropTable(
                name: "refresh_tokens");

            migrationBuilder.DropTable(
                name: "users");
        }
    }
}
