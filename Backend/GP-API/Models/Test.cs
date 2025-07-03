
namespace GP_API.Models
{
    public class Test
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Category { get; set; }
        public int QuestionNo { get; set; }
        public List<Question>? Questions { get; set; }
        public List<TestChildren>? TestChildrens { get; set; }
    }
}
