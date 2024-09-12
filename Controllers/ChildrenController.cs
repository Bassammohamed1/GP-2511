using GP_API.Models;
using GP_API.Models.DTOs;
using GP_API.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
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
        [Authorize(Roles = "Admin")]
        public IActionResult GetAllChildren()
        {
            var children = childrenService.GetAllChildren();
            return Ok(children);
        }
        [HttpGet("GetChildById/{id}")]
        [Authorize(Roles = "User")]
        public IActionResult GetChildById(int id)
        {
            if (id == 0 || id == null)
                return BadRequest("Invalid Id !!");

            var child = childrenService.GetChildById(id);

            if (child == null)
                return BadRequest("Invalid Id !!");

            return Ok(child);
        }
        [HttpGet("GetUserChildren")]
        [Authorize(Roles = "User")]
        public async Task<IActionResult> GetUserChildren()
        {
            var userId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userId))
                return BadRequest("Invalid token.");

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
                return BadRequest("User not found.");

            var children = childrenService.GetChildrenByParentId(userId);
            if (children == null)
                return BadRequest("Invalid Id !!");

            var data = new List<ChildViewDTO>();

            foreach (var child in children)
            {
                data.Add(new ChildViewDTO { Name = child.Name, Age = child.Age, Gender = child.Gender, ParentUserName = user.UserName, Image = child.Image });
            }

            return Ok(data);
        }
        [HttpPost("AddChild")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AddChild(ChildDTO data)
        {
            if (ModelState.IsValid)
            {
                var parent = await userManager.FindByNameAsync(data.ParentUserName);
                if (parent == null)
                    return BadRequest("Invalid parent name !!");

                var webRootPath = _environment.WebRootPath;
                var fileName = Path.GetRandomFileName() + Path.GetExtension(data.Image.FileName);
                var filePath = Path.Combine(webRootPath, "files/uploads/images", fileName);

                Directory.CreateDirectory(Path.GetDirectoryName(filePath));

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await data.Image.CopyToAsync(stream);
                }

                var child = new Child()
                {
                    Name = data.Name,
                    Age = data.Age,
                    ParentId = parent.Id,
                    Gender = data.Gender,
                    Image = $"{Request.Scheme}://{Request.Host}/files/uploads/images/{fileName}"
                };

                childrenService.AddChild(child);

                return Ok("Child added!!");
            }
            return BadRequest();
        }
        [HttpPut("UpdateChild/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateChild(int id, ChildDTO data)
        {
            if (ModelState.IsValid)
            {
                var parent = await userManager.FindByNameAsync(data.ParentUserName);
                if (parent == null)
                    return BadRequest("Invalid parent name !!");

                var child = childrenService.GetChildById(id);
                if (child is null)
                    return BadRequest("Invalid Id !!");


                var webRootPath = _environment.WebRootPath;
                var fileName = Path.GetRandomFileName() + Path.GetExtension(data.Image.FileName);
                var filePath = Path.Combine(webRootPath, "files/uploads/images", fileName);

                Directory.CreateDirectory(Path.GetDirectoryName(filePath));

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await data.Image.CopyToAsync(stream);
                }

                child.Name = data.Name;
                child.Age = data.Age;
                child.Gender = data.Gender;
                child.ParentId = parent.Id;
                child.Image = $"{Request.Scheme}://{Request.Host}/files/uploads/images/{fileName}";

                return Ok("Child Updated !!");
            }
            return BadRequest();
        }
        [HttpDelete("Delete Child")]
        [Authorize(Roles = "Admin")]
        public IActionResult DeleteChild(int id)
        {
            var child = childrenService.GetChildById(id);
            if (child is null)
                return BadRequest("Invalid Id !!");

            childrenService.DeleteChild(child);

            return Ok("Child deleted !!");
        }
    }
}
