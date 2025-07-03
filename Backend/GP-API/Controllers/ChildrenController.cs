using Azure;
using GP_API.Models;
using GP_API.Models.DTOs;
using GP_API.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.JsonPatch;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace GP_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ChildrenController : ControllerBase
    {
        private readonly IChildsService childrenService;
        private readonly UserManager<AppUser> userManager;
        private readonly IWebHostEnvironment _environment;
        public ChildrenController(IChildsService childrenService, UserManager<AppUser> userManager, IWebHostEnvironment environment)
        {
            this.childrenService = childrenService;
            this.userManager = userManager;
            _environment = environment;
        }
        [HttpGet("GetAllChildren")]
        [Authorize(Roles = "Specialist")]
        public IActionResult GetAllChildren()
        {
            var children = childrenService.GetAllChildren();
            return Ok(children);
        }
        [HttpGet("GetChildById/{id}")]
        [Authorize(Roles = "User,Specialist")]
        public IActionResult GetChildById(int id)
        {
            if (id == 0 || id == null)
                return BadRequest(new APIResponse { Message = "Invalid id.", StatusCode = 400 });

            var child = childrenService.GetChildById(id);

            if (child == null)
                return NotFound(new APIResponse { Message = "Child not found.", StatusCode = 404 });

            return Ok(new
            {
                Id = child.Id,
                Name = child.Name,
                Age = child.Age,
                Difficult = child.Difficult,
                ReadingDays = child.ReadingDays ?? 0,
                WritingDays = child.WritingDays ?? 0,
                LastReadingTime = child.LastReadingTime,
                LastWritingTime = child.LastWritingTime,
                ReadingRate = child.ReadingRate ?? 0,
                WritingRate = child.WritingRate ?? 0,
                ParentId = child.ParentId,
                Gender = child.Gender,

                Image = child.Image
            });
        }
        [HttpGet("GetUserChildren")]
        [Authorize(Roles = "User")]
        public async Task<IActionResult> GetUserChildren()
        {
            var userId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userId))
                return BadRequest(new APIResponse { Message = "Invalid token.", StatusCode = 404 });

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
                return BadRequest(new APIResponse { Message = "User not found.", StatusCode = 404 });

            var children = childrenService.GetChildrenByParentId(userId);
            if (children == null)
                return BadRequest(new APIResponse { Message = "Invalid id.", StatusCode = 404 });

            var data = new List<ChildViewDTO>();

            foreach (var child in children)
            {
                data.Add(new ChildViewDTO
                {
                    Id = child.Id,
                    Name = child.Name,
                    Age = child.Age,
                    Gender = child.Gender,
                    ParentUserName = user.UserName,
                    Difficult = child.Difficult,
                    ReadingDays = child.ReadingDays ?? 0,
                    WritingDays = child.WritingDays ?? 0,
                    LastReadingTime = child.LastReadingTime,
                    LastWritingTime = child.LastWritingTime,
                    ReadingRate = child.ReadingRate ?? 0,
                    WritingRate = child.WritingRate ?? 0,
                    Image = child.Image
                });
            }

            return Ok(data);
        }
        [HttpPost("AddChild")]
        [Authorize(Roles = "User")]
        public async Task<IActionResult> AddChild([FromForm] ChildDTO data)
        {
            if (ModelState.IsValid)
            {
                var parent = await userManager.FindByNameAsync(data.ParentUserName);

                if (parent == null)
                    return BadRequest(new APIResponse { Message = "Invalid parent name !!", StatusCode = 404 });

                var webRootPath = _environment.WebRootPath;

                if (data.ClientFile == null)
                {
                    return BadRequest(new APIResponse { Message = "Client file is missing", StatusCode = 404 });
                }

                var fileName = Guid.NewGuid().ToString() + Path.GetExtension(data.ClientFile.FileName);
                var filePath = Path.Combine(webRootPath, "files/uploads/images", fileName);

                Directory.CreateDirectory(Path.GetDirectoryName(filePath));

                try
                {
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await data.ClientFile.CopyToAsync(stream);
                    }
                }
                catch (Exception ex)
                {
                    return StatusCode(500, "Error saving file: " + ex.Message);
                }

                var Child = new Child()
                {
                    Name = data.Name,
                    Age = data.Age,
                    ParentId = parent.Id,
                    Difficult = data.Difficult,
                    Gender = data.Gender,
                    Image = $"{Request.Scheme}://{Request.Host}/files/uploads/images/{fileName}"
                };

                childrenService.AddChild(Child);

                var child = childrenService.GetChildById(Child.Id);

                if (child != null)
                    return Ok(new
                    {
                        Id = child.Id,
                        Name = child.Name,
                        Age = child.Age,
                        Difficult = child.Difficult,
                        ParentId = child.ParentId,
                        Gender = child.Gender,
                        Image = child.Image
                    });
                else
                    return BadRequest(new APIResponse { Message = "An error occurred.", StatusCode = 404 });
            }
            return BadRequest(ModelState);
        }
        [HttpPut("UpdateChild/{id}")]
        [Authorize(Roles = "User")]
        public async Task<IActionResult> UpdateChild(int id, [FromForm] ChildDTO data)
        {
            if (ModelState.IsValid)
            {
                var parent = await userManager.FindByNameAsync(data.ParentUserName);

                if (parent == null)
                    return BadRequest(new APIResponse { Message = "Invalid parent name !!", StatusCode = 404 });

                var child = childrenService.GetChildById(id);

                if (child is null)
                    return BadRequest(new APIResponse { Message = "Invalid id.", StatusCode = 404 });

                var webRootPath = _environment.WebRootPath;

                if (data.ClientFile == null)
                {
                    return BadRequest(new APIResponse { Message = "Client file is missing", StatusCode = 404 });
                }

                var fileName = Guid.NewGuid().ToString() + Path.GetExtension(data.ClientFile.FileName);
                var filePath = Path.Combine(webRootPath, "files/uploads/images", fileName);

                Directory.CreateDirectory(Path.GetDirectoryName(filePath));

                try
                {
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await data.ClientFile.CopyToAsync(stream);
                    }
                }
                catch (Exception ex)
                {
                    return StatusCode(500, "Error saving file: " + ex.Message);
                }

                child.Name = data.Name;
                child.Age = data.Age;
                child.Gender = data.Gender;
                child.Difficult = data.Difficult;
                child.ParentId = parent.Id;
                child.Image = $"{Request.Scheme}://{Request.Host}/files/uploads/images/{fileName}";

                childrenService.UpdateChild(child);

                return Ok(new
                {
                    Id = child.Id,
                    Name = child.Name,
                    Age = child.Age,
                    Difficult = child.Difficult,
                    ParentId = child.ParentId,
                    Gender = child.Gender,
                    Image = child.Image
                });
            }
            return BadRequest(ModelState);
        }
        [HttpDelete("DeleteChild/{id}")]
        [Authorize(Roles = "User")]
        public IActionResult DeleteChild(int id)
        {
            var child = childrenService.GetChildById(id);
            if (child is null)
                return BadRequest(new APIResponse { Message = "Invalid Id !!", StatusCode = 404 });

            childrenService.DeleteChild(child);

            return Ok(new APIResponse { Message = "Child deleted.", StatusCode = 200 });
        }
        [HttpPatch("UpdateChildReadingAndWritingDetails/{id}")]
        [Authorize(Roles = "User,Specialist")]
        public IActionResult UpdateChildReadingAndWritingDetails([FromBody] JsonPatchDocument<Child> data, int id)
        {
            if (ModelState.IsValid)
            {
                var child = childrenService.GetChildById(id);

                if (child != null)
                {
                    data.ApplyTo(child);
                    childrenService.SaveChanges();
                    return Ok(child);
                }
                else
                    return NotFound(new APIResponse { Message = "Invalid child id.", StatusCode = 404 });
            }
            else
                return BadRequest(ModelState);
        }
    }
}
