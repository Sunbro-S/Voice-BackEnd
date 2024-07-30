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
    
    
    public async Task<List<UserSerchResponse>> GetUserByLogin(HttpResponse response, string friendName, string token, int page = 1, int pageSize = 10)
    {
        var userEmail = GetClaimFromAccessToken(token, ClaimTypes.Email);
        var user = await _userManager.FindByEmailAsync(userEmail);
        if (user is null || user.RefreshTokenExpiry < DateTime.UtcNow)
            return null;

        var friendList = await _context.FriendLists.FindAsync(user.Id);
        var list = friendList.FriendList;

        IQueryable<UserEntity> query;

        if (string.IsNullOrEmpty(friendName))
        {
            query = _context.Users
                .Where(u => !list.Contains(u.UserId) && u.UserId != user.Id);
        }
        else
        {
            var lowerCaseQuery = friendName.ToLower();
            query = _context.Users
                .Where(u => !list.Contains(u.UserId) && u.UserId != user.Id && (u.UserName.ToLower().Contains(lowerCaseQuery) ||
                                                         (u.Lastname + " " + u.Name + " " + u.Otchestvo).ToLower().Contains(lowerCaseQuery)));
        }

        int totalCount = await query.CountAsync();
        response.Headers["X-Total-Count"] = totalCount.ToString();

        var users = await query
            .Select(u => new UserSerchResponse
            {
                Username = u.UserName,
                Fullname = $"{u.Lastname} {u.Name} {u.Otchestvo}",
                Id = u.UserId
            })
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return users;
    }

    public async Task<List<UserSerchResponse>> GetFriendList(HttpRequest request, HttpResponse response, string friendName,
    int page = 1, int pageSize = 10)
{
    string authHeader = request.Headers["Authorization"].FirstOrDefault();
    if (authHeader == null || !authHeader.StartsWith("Bearer "))
    {
        response.StatusCode = StatusCodes.Status401Unauthorized;
        return null;
    }

    string accessToken = authHeader.Substring("Bearer ".Length).Trim();
    var userEmail = GetClaimFromAccessToken(accessToken, ClaimTypes.Email);
    var user = await _userManager.FindByEmailAsync(userEmail);
    if (user is null || user.RefreshTokenExpiry < DateTime.UtcNow)
    {
        response.StatusCode = StatusCodes.Status401Unauthorized;
        return null;
    }

    var friendList = await _context.FriendLists.FindAsync(user.Id);
    var list = friendList.FriendList;

    List<UserSerchResponse> users;

    if (string.IsNullOrEmpty(friendName))
    {
        users = await _context.Users
            .Where(u => list.Contains(u.UserId) && u.UserId != user.Id)
            .Select(u => new UserSerchResponse
            {
                Username = u.UserName,
                Fullname = $"{u.Lastname} {u.Name} {u.Otchestvo}",
                Id = u.UserId
            })
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
    }
    else
    {
        var lowerCaseQuery = friendName.ToLower();
        users = await _context.Users
            .Where(u => list.Contains(u.UserId) 
                        && u.UserId != user.Id 
                        && (u.UserName.ToLower().Contains(lowerCaseQuery) 
                            || (u.Lastname + " " + u.Name + " " + u.Otchestvo).ToLower().Contains(lowerCaseQuery)))
            .Select(u => new UserSerchResponse
            {
                Username = u.UserName,
                Fullname = $"{u.Lastname} {u.Name} {u.Otchestvo}",
                Id = u.UserId
            })
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
    }

    int totalCount = list.Count;
    response.Headers["X-Total-Count"] = totalCount.ToString();

    return users;
}
    
    public async Task<Tuple<bool,string,string>>AddFriendAsync(string user, string friend)
    {
        var friendModel = await _userManager.FindByNameAsync(friend);
        var userModel = await _userManager.FindByNameAsync(user);
        var userId = userModel.Id;
        var friendId = friendModel.Id;
        
        var existingUser = await _context.FriendLists
            .FirstOrDefaultAsync(u => u.Id == userId);
        var exFriend = await _context.FriendLists.FirstOrDefaultAsync(u => u.Id == friendId);
        
        if (existingUser.FriendList.Contains(friendId))
            return new Tuple<bool, string, string>(false,"false","false");
        
        existingUser.FriendList.Add(friendId);
        exFriend.FriendList.Add(userId);
        _context.FriendLists.Update(existingUser);
        _context.FriendLists.Update(exFriend);
        await _context.SaveChangesAsync();
        return new Tuple<bool, string, string>(true,userId,friendId);
    }
    
    public async Task<bool> DeleteFriendAsync(string user, string friend)
    {
        var friendModel = await _userManager.FindByNameAsync(friend);
        var userModel = await _userManager.FindByNameAsync(user);
        var userId = userModel.Id;
        var friendId = friendModel.Id;

        var existingUser = await _context.FriendLists
            .FirstOrDefaultAsync(u => u.Id == userId);
        var exFriend = await _context.FriendLists.FirstOrDefaultAsync(u => u.Id == friendId);

        if (existingUser == null || exFriend == null)
            return false;


        if (!existingUser.FriendList.Contains(friendId))
            return false;
        

        existingUser.FriendList.Remove(friendId);
        exFriend.FriendList.Remove(userId);
        _context.FriendLists.Update(existingUser);
        _context.FriendLists.Update(exFriend);
        await _context.SaveChangesAsync();

        return true;
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