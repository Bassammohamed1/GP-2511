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
                var fileName = Path.GetRandomFileName() + Path.GetExtension(data.ClientFile.FileName);
                var filePath = Path.Combine(webRootPath, "files/uploads/images", fileName);

                Directory.CreateDirectory(Path.GetDirectoryName(filePath));

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await data.ClientFile.CopyToAsync(stream);
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
                    await _userManager.AddToRoleAsync(user, "User");

                    var claims = new List<Claim>();
                    claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));
                    claims.Add(new Claim(ClaimTypes.Email, user.Email));
                    claims.Add(new Claim(ClaimTypes.Name, user.UserName));
                    claims.Add(new Claim("UserImage", user.Image));
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
                return BadRequest("Invalid token.");

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return BadRequest("User not found.");

            var webRootPath = _environment.WebRootPath;
            var fileName = Path.GetRandomFileName() + Path.GetExtension(data.ClientFile.FileName);
            var filePath = Path.Combine(webRootPath, "files/uploads/images", fileName);

            Directory.CreateDirectory(Path.GetDirectoryName(filePath));

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await data.ClientFile.CopyToAsync(stream);
            }

            user.UserName = data.UserName;
            user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, data.Password);
            user.Email = data.Email;
            user.Image = $"{Request.Scheme}://{Request.Host}/files/uploads/images/{fileName}";

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            return Ok("User updated!");
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
                        claims.Add(new Claim("UserImage", User.Image));
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
                    return BadRequest("Invalid email or password");
                }
                return BadRequest("Invalid email or password");
            }
            return BadRequest();
        }
        [HttpPost("Logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            _tokenService.InvalidateToken(userId);

            return Ok(new { message = "Logged out successfully." });
        }
    }
}