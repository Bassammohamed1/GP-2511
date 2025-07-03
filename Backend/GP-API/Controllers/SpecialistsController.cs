using GP_API.Data;
using GP_API.Models;
using GP_API.Models.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GP_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SpecialistsController : ControllerBase
    {
        private readonly AppDbContext _context;
        public SpecialistsController(AppDbContext context)
        {
            _context = context;
        }
        [HttpGet("GetChildTests/{id}")]
        [Authorize(Roles = "User")]
        public IActionResult GetChildTests(int id)
        {
            var testIds = _context.TestChildrens.Where(t => t.ChildId == id).Select(t => t.TestId).Distinct().ToList();

            var testData = new List<TestDTO>();

            foreach (var testId in testIds)
            {
                var test = _context.Tests.SingleOrDefault(t => t.Id == testId);
                if (test != null)
                {
                    var questions = _context.Questions.Where(q => q.TestId == testId).ToList();

                    var testDTO = new TestDTO()
                    {
                        TestName = test.Name,TestCategory = test.Category
                        ,
                        QuestionsNo = test.QuestionNo,
                        Questions = questions.Select(q => new QuestionDTO
                        {
                            QuestionText = q.QuestionText,
                            QuestionType = q.QuestionType,
                            QuestionAnswer = q.QuestionAnswer
                        }).ToList()
                    };

                    testData.Add(testDTO);
                }
            }

            return Ok(testData);
        }

        [HttpPost("CreateTest")]
        [Authorize(Roles = "Specialist")]
        public IActionResult CreateTest([FromBody] CreateTestDTO testDTO)
        {
            var test = new Test()
            {
                Name = testDTO.TestName,
                Category = testDTO.TestCategory,
                QuestionNo = testDTO.QuestionsNo
            };
            _context.Tests.Add(test);
            _context.SaveChanges();

            foreach (var childId in testDTO.ChildrenId)
            {
                var data1 = new TestChildren()
                {
                    ChildId = childId,
                    TestId = test.Id
                };
                _context.TestChildrens.Add(data1);
            }
            _context.SaveChanges();

            foreach (var question in testDTO.Questions)
            {
                var data2 = new Question()
                {
                    QuestionText = question.QuestionText,
                    QuestionType = question.QuestionType,
                    QuestionAnswer = question.QuestionAnswer,
                    TestId = test.Id,
                };
                _context.Questions.Add(data2);
            }
            _context.SaveChanges();

            return Ok(new APIResponse { Message = "Test has been created successfully.", StatusCode = 200 });
        }

    }
}
