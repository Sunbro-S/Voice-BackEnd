using IdentityApi.Models;
using Microsoft.AspNetCore.Http;

namespace Infrastructure.Services.Interfaces;

public interface IAuthService
{
    
    Task<LoginResponse> Login(LoginRequest user);
    Task<LoginResponse> RefreshToken(RefreshTokenModel model);
    Task<bool> AddUserWithRoles(RegisterRequest userInfo);
    Task<LoginResponse> Logout(HttpRequest request);
    Task<UserSerchResponse> GetUserByLogin(string friendName);
    Task<List<string>> GetFriendList(HttpRequest request);
    Task<LoginResponse> DeleteAccount(HttpRequest request);
    Task<LoginResponse> PutAccountChanges(HttpRequest request, UpdateUserDataRequest updateUserModel);
}