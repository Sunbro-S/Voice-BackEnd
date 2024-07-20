using Domain;
using Domain.Models;
using Microsoft.AspNetCore.Http;

namespace Services.Services.Interfaces;

public interface IAuthService
{
    
    Task<Tuple<int,List<UserSerchResponse>>> GetUserByLogin(string friendName ,string token,int page = 1, int pageSize = 10);
    Task<List<string>> GetFriendList(HttpRequest request);
    
    Task<Tuple<bool,string,string>> AddUserAsync(string user, string friend);
}