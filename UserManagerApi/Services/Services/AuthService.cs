using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Domain;
using Domain.Models;
using Infrastructure;
using Infrastructure.Data.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Abstractions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Services.Services.Interfaces;


namespace Services.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<ExtendedIdentityUser> _userManager;
    private readonly IConfiguration _config;
    private readonly ContextDb _context;
    
    
    public AuthService(UserManager<ExtendedIdentityUser> userManager, IConfiguration config, ContextDb context)
    {
        _userManager = userManager;
        _config = config;
        _context = context;
    }
    
    
    public async Task<Tuple<int,List<UserSerchResponse>>> GetUserByLogin(string friendName,string token ,int page = 1, int pageSize = 10)
    {
        var userEmail = GetClaimFromAccessToken(token, ClaimTypes.Email);
        var user = await _userManager.FindByEmailAsync(userEmail);
        var friendList = await _context.FriendLists.FindAsync(user.Id);
        var list = friendList.FriendList;
        
        if (string.IsNullOrEmpty(friendName))
        {
            var allUsers = await _context.Users
                .Where(u =>!list.Contains(u.UserId))
                .Select(u => new UserSerchResponse
                {
                    Username = u.UserName,
                    Fullname = $"{u.Lastname} {u.Name} {u.Otchestvo}"
                })
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();
            var allResult = new Tuple<int, List<UserSerchResponse>>(allUsers.Count, allUsers);

            return allResult;
        }

        var lowerCaseQuery = friendName.ToLower();

        var users = await _context.Users
            .Where(u =>!list.Contains(u.UserId) && (u.UserName.ToLower().Contains(lowerCaseQuery) ||
                        (u.Lastname + " " + u.Name + " " + u.Otchestvo).ToLower().Contains(lowerCaseQuery)))
            .Select(u => new UserSerchResponse
            {
                Username = u.UserName,
                Fullname = $"{u.Lastname} {u.Name} {u.Otchestvo}"
            })
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
        var result = new Tuple<int, List<UserSerchResponse>>(users.Count, users);
        return result;
    }

    public async Task<List<string>> GetFriendList(HttpRequest request)
    {
        string authHeader = request.Headers["Authorization"].FirstOrDefault();
        if (authHeader == null || !authHeader.StartsWith("Bearer "))
        {
            return null;
        }

        string accessToken = authHeader.Substring("Bearer ".Length).Trim();
        var response = new LoginResponse();
        var userEmail = GetClaimFromAccessToken(accessToken, ClaimTypes.Email);
        var user = await _userManager.FindByEmailAsync(userEmail);
        var friendList = await _context.FriendLists.FindAsync(user.Id);
        return friendList.FriendList;

    }
    
    public async Task<Tuple<bool,string,string>>AddUserAsync(string user, string friend)
    {
        var friendModel = await _userManager.FindByNameAsync(friend);
        var userModel = await _userManager.FindByNameAsync(user);
        var userId = userModel.Id;
        var friendId = friendModel.Id;
        
        var existingUser = await _context.FriendLists
            .FirstOrDefaultAsync(u => u.Id == userId);
        
        if (existingUser.FriendList.Contains(friendId))
        {
            return new Tuple<bool, string, string>(false,"Хуй","Хуй");
        }
        existingUser.FriendList.Add(friendId);
        _context.FriendLists.Update(existingUser);
        await _context.SaveChangesAsync();
        return new Tuple<bool, string, string>(true,userId,friendId);
    }

    
    private string GetClaimFromAccessToken(string accessToken, string claimType)
    {
        var claims = DecodeAccessToken(accessToken);
        var claim = claims.FirstOrDefault(c => c.Type == claimType);
        return claim?.Value;
    }
    
    private List<Claim> DecodeAccessToken(string accessToken)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_config.GetSection("Jwt:Key").Value);

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _config.GetSection("Jwt:Issuer").Value,
            ValidAudience = _config.GetSection("Jwt:Audience").Value,
            IssuerSigningKey = new SymmetricSecurityKey(key)
        };

        try
        {
            var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters,
                out SecurityToken validatedToken);
            return principal.Claims.ToList();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка при расшифровке токена: {ex.Message}");
            return null;
        }
    }
}