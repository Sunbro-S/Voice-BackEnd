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
            return BadRequest("The user was created or the conditions were not met");
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginRequest user)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("Something went wrong");
            }
            var loginResult = await _authService.Login(user);
            if (loginResult.Tokens.IsLogedIn)
            {
                return Ok(loginResult);
            }
            return Unauthorized("Invalid login or password");
        }

        [HttpPost("Logout")]
        public async Task<IActionResult> Logout()
        {
            
          var loginResult = await _authService.Logout(Request);
          if (loginResult == null)
              return BadRequest("Invalid token");
          return Ok(loginResult);
            
        }

        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken(RefreshTokenModel model)
        {
            var loginResult = await _authService.RefreshToken(model);
            if (loginResult.Tokens.IsLogedIn)
            {
                return Ok(loginResult);
            }
            return BadRequest("Invalid token or token has been expired");
        }

        [HttpGet("FriendList")]
        public async Task<IActionResult> GetFriendList()
        {
            var result = await _authService.GetFriendList(Request);
            if (result==null)
                return BadRequest("Could not get friend list");
            return Ok(result);
        }

        [HttpGet("GetUser")]
        public async Task<IActionResult> GetUserByLogin(string friendName)
        {
            var result = await _authService.GetUserByLogin(friendName);
            if (result==null)
                return BadRequest("User was not found");
            return Ok(result);
        }

       

        [HttpDelete("DeleteAccount")]
        public async Task<IActionResult> DeleteAccount()
        {
            var result = await _authService.DeleteAccount(Request);
            if (result==null)
                return BadRequest("Something went wrong");
            return Ok("User account deleted successfully" );
            
        }

        [HttpPut("PutAccountChanges")]
        public async Task<IActionResult> PutAccountChanges(UpdateUserDataRequest updateUserModel)
        {
            var result = await _authService.PutAccountChanges(Request, updateUserModel);
            if (result==null)
                return BadRequest("Failed to update user account");
            return Ok(result);
        }
    }
}
