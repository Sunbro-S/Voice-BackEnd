using Domain.Models;
using Microsoft.AspNetCore.Http;

namespace Services.Services.Interfaces;

public interface IAuthService
{
    
    Task<LoginResponse> Login(LoginRequest user);
    Task<LoginResponse> RefreshToken(RefreshTokenModel model);
    Task<bool> AddUserWithRoles(RegisterRequest userInfo);
    Task<LoginResponse> Logout(HttpRequest request);
    Task<LoginResponse> DeleteAccount(HttpRequest request);
    Task<LoginResponse> PutAccountChanges(HttpRequest request, UpdateUserDataRequest updateUserModel);
}