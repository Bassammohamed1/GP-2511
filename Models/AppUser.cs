using Microsoft.AspNetCore.Identity;

namespace GP_API.Models
{
    public class AppUser : IdentityUser
    {
        public string Image { get; set; }
        public List<Child> Children { get; set; }
    }
}
