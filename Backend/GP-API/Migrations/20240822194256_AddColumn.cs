using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace GP_API.Migrations
{
    /// <inheritdoc />
    public partial class AddColumn : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "1cb3353d-910e-4799-83b9-53aa7fe7c4c0");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "407e52b0-d0e8-4d84-b9f5-b7560921ccdb");

            migrationBuilder.AddColumn<byte[]>(
                name: "Image",
                table: "AspNetUsers",
                type: "varbinary(max)",
                nullable: false,
                defaultValue: new byte[0]);

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "469e21b1-d600-4b5e-9c55-73b4942a8e4c", "db46af4e-435f-49e5-b0af-87652539a8f1", "User", "USER" },
                    { "6c4b242e-a6bf-4cf0-80a5-76ce79914081", "6a472a1b-be84-48f0-be61-a627060a59ce", "Admin", "ADMIN" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "469e21b1-d600-4b5e-9c55-73b4942a8e4c");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "6c4b242e-a6bf-4cf0-80a5-76ce79914081");

            migrationBuilder.DropColumn(
                name: "Image",
                table: "AspNetUsers");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "1cb3353d-910e-4799-83b9-53aa7fe7c4c0", "aaaf9543-49e4-4c34-89ba-3f63b0d881c8", "Admin", "ADMIN" },
                    { "407e52b0-d0e8-4d84-b9f5-b7560921ccdb", "0b043b82-e513-4e41-b4c5-8c5560e513f2", "User", "USER" }
                });
        }
    }
}
