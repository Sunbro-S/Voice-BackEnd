using Domain.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Services.Services.Interfaces;

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
            return BadRequest("Пользователь уже был создан или не были выполнены условия!");
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginRequest user)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("Что-то пошло не так");
            }
            var loginResult = await _authService.Login(user);
            if (loginResult.Tokens.IsLogedIn)
            {
                return Ok(loginResult);
            }
            return BadRequest("Неверный логин или пароль!");
        }

        [HttpPost("Logout")]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var loginResult = await _authService.Logout(Request);
                if (loginResult == null)
                    return Unauthorized("Invalid token or token expired");

                return Ok(loginResult);
            }
            catch (ArgumentNullException ex)
            {
                return Unauthorized("Invalid token or token expired");
            }
        }

        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken(RefreshTokenModel model)
        {
            var loginResult = await _authService.RefreshToken(model);
            if (loginResult.Tokens.IsLogedIn)
            {
                return Ok(loginResult);
            }
            return Unauthorized("Invalid token or token has been expired");
        }

        
        [HttpDelete("DeleteAccount")]
        public async Task<IActionResult> DeleteAccount()
        {
            var result = await _authService.DeleteAccount(Request);
            if (result==null)
                return BadRequest("Something went wrong");
            return Ok("User account deleted successfully");
            
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
