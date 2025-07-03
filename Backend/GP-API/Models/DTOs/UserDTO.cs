using System.ComponentModel.DataAnnotations;

namespace GP_API.Models.DTOs
{
    public class UserDTO
    {
        public string UserName { get; set; }
        [EmailAddress]
        public string Email { get; set; }
        [MinLength(8)]
        public string Password { get; set; }
        [Range(1, 2)]
        public int RoleNo { get; set; }
        public IFormFile ClientFile { get; set; }
    }
}
