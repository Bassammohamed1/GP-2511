
namespace GP_API.Models.DTOs
{
    public class UserViewDTO
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Image { get; set; }
        public List<string> Roles { get; set; }
    }
}
