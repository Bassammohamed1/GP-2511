using GP_API.Data;
using System.ComponentModel.DataAnnotations.Schema;

namespace GP_API.Models
{
    public class Child
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public int Age { get; set; }
        public Gender Gender { get; set; }
        public string Image { get; set; }
        public int? ReadingRate {get; set; }
        public int? WritingRate {get; set; }
        public string? LastReadingTime {get; set; }
        public string? LastWritingTime {get; set; }
        public int? ReadingDays {get; set; }
        public int? WritingDays {get; set; }
        public string Difficult {get; set; }
        public string ParentId { get; set; }
        [ForeignKey(nameof(ParentId))]
        public AppUser? Parent { get; set; }
        public List<TestChildren>? TestChildrens { get; set; }
    }
}
