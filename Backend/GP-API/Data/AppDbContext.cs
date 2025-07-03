using GP_API.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace GP_API.Data
{
    public class AppDbContext : IdentityDbContext<AppUser>
    {
        public AppDbContext(DbContextOptions options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<TestChildren>().HasKey(k => new { k.TestId, k.ChildId });

            builder.Entity<TestChildren>().HasOne(c => c.Child).WithMany(c => c.TestChildrens).HasForeignKey(c => c.ChildId);
            builder.Entity<TestChildren>().HasOne(c => c.Test).WithMany(c => c.TestChildrens).HasForeignKey(c => c.TestId);

            base.OnModelCreating(builder);
        }
        public DbSet<UserToken> Tokens { get; set; }
        public DbSet<Child> Children { get; set; }
        public DbSet<Test> Tests { get; set; }
        public DbSet<TestChildren> TestChildrens { get; set; }
        public DbSet<Question> Questions { get; set; }
    }
}
