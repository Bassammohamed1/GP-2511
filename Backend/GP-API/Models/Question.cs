using System.ComponentModel.DataAnnotations.Schema;

namespace GP_API.Models
{
    public class Question
    {
        public int QuestionId { get; set; }
        public string QuestionText { get; set; }
        public string QuestionAnswer { get; set; }
        public string QuestionType { get; set; }
        public int TestId { get; set; }
        [ForeignKey(nameof(TestId))]
        public Test? Test { get; set; }
    }
}
