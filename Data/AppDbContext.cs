using GP_API.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace GP_API.Data
{
    public class AppDbContext : IdentityDbContext<AppUser>
    {
        public AppDbContext(DbContextOptions options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            //builder.Entity<IdentityRole>().HasData(
            //    new IdentityRole
            //    {
            //        Id = Guid.NewGuid().ToString(),
            //        Name = "Admin",
            //        NormalizedName = "ADMIN",
            //        ConcurrencyStamp = Guid.NewGuid().ToString()
            //    },
            //    new IdentityRole
            //    {
            //        Id = Guid.NewGuid().ToString(),
            //        Name = "User",
            //        NormalizedName = "USER",
            //        ConcurrencyStamp = Guid.NewGuid().ToString()
            //    });

            base.OnModelCreating(builder);
        }
        public DbSet<UserToken> Tokens { get; set; }
        public DbSet<Child> Children { get; set; }
    }
}
