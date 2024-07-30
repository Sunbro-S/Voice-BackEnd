using System.Text.Json;
using Domain.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using RPC;
using RPC.Interface;
using Services.Services.Interfaces;

namespace UserManagerApi.Controllers;

[Route("api/[controller]")]
[ApiController]
public class OrderController : ControllerBase
{
    private readonly IAuthService _authService;

    public OrderController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpGet("AddFriend")]
    public async Task<IActionResult> AddFriend(string user, string friend)
    {
        try
        {
            var result = await _authService.AddFriendAsync(user, friend);
            if (!result.Item1)
                return BadRequest("Не удалось добавить друга");
            return Ok("All good");
        }
        catch (ArgumentNullException ex)
        {
            return Unauthorized("Invalid token or token expired");
        }
    }
    
    [HttpGet("DeleteFriend")]
    public async Task<IActionResult> DeleteFriend(string user, string friend)
    {
        try
        {
            var result = await _authService.DeleteFriendAsync(user, friend);
            if (!result)
                return BadRequest("Не удалось удалить друга");
            return Ok("All good");
        }
        catch (ArgumentNullException ex)
        {
            return Unauthorized("Invalid token or token expired");
        }
    }
    
    [HttpGet("FriendList")]
    public async Task<IActionResult> GetFriendList(string? friendName, int page = 1, int pageSize = 10)
    {
        try
        {
            var result = await _authService.GetFriendList(Request, Response, friendName, page, pageSize);
            if (result == null)
                return BadRequest("Не удалось получить список друзей");
            return Ok(result);
        }
        catch (ArgumentNullException ex)
        {
            return Unauthorized("Invalid token or token expired");
        }
    }

    [HttpGet("GetUser")]
    public async Task<IActionResult> GetUserByLogin(string? friendName, int page=1, int pageSize=10)
    {
        try
        {
            string authHeader = Request.Headers["Authorization"].FirstOrDefault();
            if (authHeader == null || !authHeader.StartsWith("Bearer "))
            {
                return Unauthorized("User is not authenticated.");
            }

            string accessToken = authHeader.Substring("Bearer ".Length).Trim();
            var result = await _authService.GetUserByLogin(Response, friendName, accessToken, page, pageSize);
            if (result == null)
                return NotFound("Данный пользователь не был найден");
            return Ok(result);
        }
        catch (ArgumentNullException ex)
        {
            return Unauthorized("Invalid token or token expired");
        }
    }

}