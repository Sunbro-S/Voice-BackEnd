using Domain.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using RPC.Interface;
using Services.Services.Interfaces;

namespace UserManagerApi.Controllers;

[Route("api/[controller]")]
[ApiController]
public class OrderController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly IKafkaProducerService _producerService;

    public OrderController(IAuthService authService, IKafkaProducerService producerService)
    {
        _authService = authService;
        
        _producerService = producerService;
    }
    
    [HttpGet("FriendList")]
    public async Task<IActionResult> GetFriendList()
    {
        var result = await _authService.GetFriendList(Request);
        if (result==null)
            return BadRequest("Не удалось получить список друзей");
        return Ok(result);
    }

    [HttpGet("GetUser")]
    public async Task<IActionResult> GetUserByLogin(string? friendName, int page, int pageSize)
    {
        string authHeader = Request.Headers["Authorization"].FirstOrDefault();
        if (authHeader == null || !authHeader.StartsWith("Bearer "))
        {
            return Unauthorized("User is not authenticated.");
        }
        string accessToken = authHeader.Substring("Bearer ".Length).Trim();
        var result = await _authService.GetUserByLogin(friendName, accessToken,page, pageSize);
        if (result==null)
            return NotFound("Данный пользователь не был найден");
        return Ok(result);
    }

}