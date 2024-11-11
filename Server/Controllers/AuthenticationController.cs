using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ServerLibrary.Repositories.Contracts;

namespace Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController(IUserAccount accountInterface) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<IActionResult> CreateAsync(Register user)
        {
            if (user == null) return BadRequest("User is null");
            var response = await accountInterface.CreateAsync(user);
            return Ok(response);
        }

        [HttpPost("login")]
        public async Task<IActionResult> SignInAsync(Login user)
        {
            if (user == null) return BadRequest("User is null");
            var response = await accountInterface.SignInAsync(user);
            return Ok(response);
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshTokenAsync(string token)
        {
            if (string.IsNullOrEmpty(token)) return BadRequest("Token is null");
            var response = await accountInterface.RefreshTokenAsync(token);
            return Ok(response);
        }
    }
}
