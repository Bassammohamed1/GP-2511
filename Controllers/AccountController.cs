using GP_API.Models.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
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
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        public AccountController(UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }
        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterDTO data)
        {
            if (ModelState.IsValid)
            {
                if (data.Password == data.ConfirmPassword)
                {
                    var user = new IdentityUser() { UserName = data.UserName, Email = data.Email, PasswordHash = data.Password };
                    var result = await _userManager.CreateAsync(user, data.Password);
                    if (result.Succeeded)
                    {
                        await _userManager.AddToRoleAsync(user, "User");
                        return Ok("User Registered successfully!");
                    }
                    else
                    {
                        foreach (var item in result.Errors)
                        {
                            ModelState.AddModelError("Custom", item.Description);
                        }
                    }
                }
                else
                {
                    return BadRequest("Password and confirm password is not the same!");
                }
            }
            return BadRequest(ModelState);
        }
        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginDTO user)
        {
            if (ModelState.IsValid)
            {
                var User = await _userManager.FindByNameAsync(user.UserName);
                if (User is not null)
                {
                    if (await _userManager.CheckPasswordAsync(User, user.Password))
                    {
                        var claims = new List<Claim>();
                        claims.Add(new Claim(ClaimTypes.Name, User.UserName));
                        claims.Add(new Claim(ClaimTypes.NameIdentifier, User.Id));
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
                        return Ok(_token);
                    }
                    return BadRequest("Invalid username or password");
                }
                return BadRequest("Invalid username or password");
            }
            return BadRequest();
        }
    }
}
