using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace GP_API.Migrations
{
    /// <inheritdoc />
    public partial class ModifyChildModel : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Difficult",
                table: "Children",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "LastReadingTime",
                table: "Children",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastWritingTime",
                table: "Children",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ReadingDays",
                table: "Children",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ReadingRate",
                table: "Children",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "WritingDays",
                table: "Children",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "WritingRate",
                table: "Children",
                type: "int",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Difficult",
                table: "Children");

            migrationBuilder.DropColumn(
                name: "LastReadingTime",
                table: "Children");

            migrationBuilder.DropColumn(
                name: "LastWritingTime",
                table: "Children");

            migrationBuilder.DropColumn(
                name: "ReadingDays",
                table: "Children");

            migrationBuilder.DropColumn(
                name: "ReadingRate",
                table: "Children");

            migrationBuilder.DropColumn(
                name: "WritingDays",
                table: "Children");

            migrationBuilder.DropColumn(
                name: "WritingRate",
                table: "Children");
        }
    }
}
