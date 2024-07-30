using Domain;
using Domain.Models;
using Microsoft.AspNetCore.Http;

namespace Services.Services.Interfaces;

public interface IAuthService
{

    Task<List<UserSerchResponse>> GetUserByLogin(HttpResponse response, string friendName, string token, int page = 1,
        int pageSize = 10);

    Task<List<UserSerchResponse>> GetFriendList(HttpRequest request, HttpResponse response, string friendName,
        int page = 1, int pageSize = 10);
    
    Task<Tuple<bool,string,string>> AddFriendAsync(string user, string friend);
    Task<bool> DeleteFriendAsync(string user, string friend);
}