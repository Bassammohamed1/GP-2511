using System.ComponentModel.DataAnnotations;

namespace GP_API.Models.DTOs
{
    public class LoginDTO
    {
        public string UserName { get; set; }
        [MinLength(8)]
        public string Password { get; set; }
    }
}
