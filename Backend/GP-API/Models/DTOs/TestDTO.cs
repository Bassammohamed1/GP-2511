namespace GP_API.Models.DTOs
{
    public class TestDTO
    {
        public string TestName { get; set; }
        public string TestCategory { get; set; }
        public int QuestionsNo { get; set; }
        public List<QuestionDTO> Questions { get; set; }
    }
}
