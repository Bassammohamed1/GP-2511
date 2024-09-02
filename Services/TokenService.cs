using GP_API.Data;
using GP_API.Services.Interfaces;

namespace GP_API.Services
{
    public class TokenService : ITokenService
    {
        private readonly AppDbContext _context;

        public TokenService(AppDbContext context)
        {
            _context = context;
        }
        public void InvalidateToken(string userId)
        {
            var token = _context.Tokens.FirstOrDefault(t => t.UserId == userId);
            if (token != null)
            {
                _context.Tokens.Remove(token);
                _context.SaveChanges();
            }
        }
    }
}
