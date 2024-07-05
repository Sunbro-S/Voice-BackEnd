using IdentityApi.Models;
using Microsoft.AspNetCore.Http;

namespace Infrastructure.Services.Interfaces;

public interface IAuthService
{
    
    Task<LoginResponse> Login(LoginRequest user);
    Task<LoginResponse> RefreshToken(RefreshTokenModel model);
    Task<bool> AddUserWithRoles(RegisterRequest userInfo);
    Task<LoginResponse> Logout(HttpRequest request);
    Task<List<UserSerchResponse>> GetUserByLogin(string friendName ,int page = 1, int pageSize = 10);
    Task<List<string>> GetFriendList(HttpRequest request);
    Task<LoginResponse> DeleteAccount(HttpRequest request);
    Task<LoginResponse> PutAccountChanges(HttpRequest request, UpdateUserDataRequest updateUserModel);
}