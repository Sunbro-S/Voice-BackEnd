using IdentityApi.Models;
using Infrastructure.Services.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
namespace IdentityApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OrderController : ControllerBase
    {
        
        private readonly IAuthService _authService;

        public OrderController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> RegisterUser(RegisterRequest user)
        {
            if (await _authService.AddUserWithRoles(user))
            {
                return Ok("Successfuly done");
            }
            return BadRequest("Something went worng");
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginRequest user)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }
            var loginResult = await _authService.Login(user);
            if (loginResult.IsLogedIn)
            {
                return Ok(loginResult);
            }
            return Unauthorized();
        }

        [HttpPost("Logout")]
        public async Task<IActionResult> Logout()
        {
            
          var loginResult = await _authService.Logout(Request);
          return Ok(loginResult);
            
        }

        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken(RefreshTokenModel model)
        {
            var loginResult = await _authService.RefreshToken(model);
            if (loginResult.IsLogedIn)
            {
                return Ok(loginResult);
            }
            return Unauthorized();
        }

        [HttpGet("FriendList")]
        public async Task<IActionResult> GetFriendList()
        {
            var result = await _authService.GetFriendList(Request);
            return Ok(result);
        }

        [HttpGet("GetUser")]
        public async Task<IActionResult> GetUserByLogin(string friendName)
        {
            var result = await _authService.GetUserByLogin(friendName);
            return Ok(result);
        }

       

        [HttpDelete("DeleteAccount")]
        public async Task<IActionResult> DeleteAccount()
        {
            var result = await _authService.DeleteAccount(Request);
            if (result.IsLogedIn==false)
            {
                return Ok(new { Message = "User account deleted successfully" });
            }
            else
            {
                return BadRequest(new { Message = "Failed to delete user account" });
            }
        }

        [HttpPut("PutAccountChanges")]
        public async Task<IActionResult> PutAccountChanges(UpdateUserDataRequest updateUserModel)
        {
            var result = await _authService.PutAccountChanges(Request, updateUserModel);
            if (result.IsLogedIn==true)
            {
                return Ok(result);
            }
            else
            {
                return BadRequest(new { Message = "Failed to update user account" });
            }
        }
    }
}
