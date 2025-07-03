using GP_API.Data;
using GP_API.Models;
using GP_API.Models.DTOs;
using GP_API.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace GP_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly ITokenService _tokenService;
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _environment;
        public AccountController(UserManager<AppUser> userManager, IConfiguration configuration, ITokenService tokenService, AppDbContext context, IWebHostEnvironment environment)
        {
            _userManager = userManager;
            _configuration = configuration;
            _tokenService = tokenService;
            _context = context;
            _environment = environment;
        }
        [HttpPost("Register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromForm] UserDTO data)
        {
            if (ModelState.IsValid)
            {
                var webRootPath = _environment.WebRootPath;

                if (data.ClientFile == null)
                {
                    return BadRequest(new APIResponse { Message = "Client file is missing.", StatusCode = 404 });
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

                var user = new AppUser()
                {
                    UserName = data.UserName,
                    Email = data.Email,
                    Image = $"{Request.Scheme}://{Request.Host}/files/uploads/images/{fileName}"
                };

                var result = await _userManager.CreateAsync(user, data.Password);

                if (result.Succeeded)
                {
                    switch (data.RoleNo)
                    {
                        case 1:
                            await _userManager.AddToRoleAsync(user, "User");
                            break;
                        case 2:
                            await _userManager.AddToRoleAsync(user, "Specialist");
                            break;
                        default:
                            ModelState.AddModelError("Custom", "RoleNo must be 1 or 2.");
                            return BadRequest(ModelState);
                    }

                    var claims = new List<Claim>();
                    claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));
                    claims.Add(new Claim(ClaimTypes.Email, user.Email));
                    claims.Add(new Claim(ClaimTypes.Name, user.UserName));
                    claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

                    var roles = await _userManager.GetRolesAsync(user);
                    foreach (var role in roles)
                    {
                        claims.Add(new Claim(ClaimTypes.Role, role.ToString()));
                    }

                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]));
                    var sc = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                    var token = new JwtSecurityToken(
                        claims: claims,
                        issuer: _configuration["JWT:Issuer"],
                        audience: _configuration["JWT:Audience"],
                        expires: DateTime.Now.AddMonths(1),
                        signingCredentials: sc
                        );

                    var _token = new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(token),
                        expiration = token.ValidTo,
                        UserId = user.Id,
                        UserName = user.UserName,
                        Email = user.Email,
                        Image = user.Image,
                        Roles = roles
                    };

                    var userToken = new UserToken
                    {
                        UserId = user.Id,
                        Token = _token.token,
                        Expiration = _token.expiration
                    };

                    _context.Tokens.Add(userToken);
                    await _context.SaveChangesAsync();

                    return Ok(_token);
                }
                else
                {
                    foreach (var item in result.Errors)
                    {
                        ModelState.AddModelError("Custom", item.Description);
                    }
                }
            }
            return BadRequest(ModelState);
        }
        [HttpPut("UpdateUser")]
        [Authorize(Roles = "User")]
        public async Task<IActionResult> UpdateUser([FromForm] UserDTO data)
        {
            var userId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userId))
                return BadRequest(new APIResponse { Message = "Invalid token.", StatusCode = 404 });

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return BadRequest(new APIResponse { Message = "User not found.", StatusCode = 404 });

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
            var userRole = await _userManager.GetRolesAsync(user);
            string role = userRole.First();

            user.UserName = data.UserName;
            user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, data.Password);
            user.Email = data.Email;
            user.Image = $"{Request.Scheme}://{Request.Host}/files/uploads/images/{fileName}";

            if (data.RoleNo == 1 && role != "User")
            {
                await _userManager.RemoveFromRoleAsync(user, "Specialist");
                await _userManager.AddToRoleAsync(user, "User");
            }
            else if (data.RoleNo == 2 && role != "Specialist")
            {
                await _userManager.RemoveFromRoleAsync(user, "User");
                await _userManager.AddToRoleAsync(user, "Specialist");
            }

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            return Ok(new APIResponse { Message = "User updated.", StatusCode = 200 });
        }
        [HttpPost("Login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginDTO user)
        {
            if (ModelState.IsValid)
            {
                var User = await _userManager.FindByEmailAsync(user.Email);
                if (User is not null)
                {
                    if (await _userManager.CheckPasswordAsync(User, user.Password))
                    {
                        var claims = new List<Claim>();
                        claims.Add(new Claim(ClaimTypes.NameIdentifier, User.Id));
                        claims.Add(new Claim(ClaimTypes.Email, User.Email));
                        claims.Add(new Claim(ClaimTypes.Name, User.UserName));
                        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

                        var roles = await _userManager.GetRolesAsync(User);
                        foreach (var role in roles)
                        {
                            claims.Add(new Claim(ClaimTypes.Role, role.ToString()));
                        }

                        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]));
                        var sc = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                        var token = new JwtSecurityToken(
                            claims: claims,
                            issuer: _configuration["JWT:Issuer"],
                            audience: _configuration["JWT:Audience"],
                            expires: DateTime.Now.AddMonths(1),
                            signingCredentials: sc
                            );

                        var _token = new
                        {
                            token = new JwtSecurityTokenHandler().WriteToken(token),
                            expiration = token.ValidTo,
                            UserId = User.Id,
                            UserName = User.UserName,
                            Email = User.Email,
                            Image = User.Image,
                            Roles = roles
                        };

                        var userToken = new UserToken
                        {
                            UserId = User.Id,
                            Token = _token.token,
                            Expiration = _token.expiration
                        };

                        _context.Tokens.Add(userToken);
                        await _context.SaveChangesAsync();

                        return Ok(_token);
                    }
                    return BadRequest(new APIResponse { Message = "Invalid email or password", StatusCode = 401 });
                }
                return BadRequest(new APIResponse { Message = "Invalid email or password", StatusCode = 401 });
            }
            return BadRequest(ModelState);
        }
        [HttpPost("Logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            _tokenService.InvalidateToken(userId);

            return Ok(new APIResponse { Message = "Logged out successfully.", StatusCode = 200 });
        }
        [HttpGet("GetUserData")]
        [Authorize(Roles = "User,Specialist,Admin")]
        public async Task<IActionResult> GetUserData()
        {
            var userId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userId))
                return BadRequest(new APIResponse { Message = "Invalid token.", StatusCode = 404 });

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return BadRequest(new APIResponse { Message = "User not found.", StatusCode = 404 });

            var userRoles = await _userManager.GetRolesAsync(user);

            var data = new UserViewDTO
            {
                Id = user.Id,
                Email = user.Email,
                UserName = user.UserName,
                Image = user.Image,
                Roles = userRoles.ToList()
            };
            return Ok(data);
        }
    }
}