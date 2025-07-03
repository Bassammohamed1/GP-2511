using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace GP_API.Migrations
{
    /// <inheritdoc />
    public partial class AddNewRole : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "298da733-5e4e-4d9d-8bc3-b4943736578f", "dad294e5-de53-4b33-83d7-223c6ffd7d79", "Specialist", "SPECIALIST" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "298da733-5e4e-4d9d-8bc3-b4943736578f");
        }
    }
}
