using GP_API.Data;

namespace GP_API.Models.DTOs
{
    public class ChildDTO
    {
        public string Name { get; set; }
        public int Age { get; set; }
        public Gender Gender { get; set; }
        public IFormFile Image { get; set; }
        public string ParentUserName { get; set; }
    }
}
