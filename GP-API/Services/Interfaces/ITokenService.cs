namespace GP_API.Services.Interfaces
{
    public interface ITokenService
    {
        void InvalidateToken(string userId);
    }
}
