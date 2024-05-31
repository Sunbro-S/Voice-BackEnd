namespace IdentityApi.Models;

public class LoginResponse
{
    
    public bool IsLogedIn { get; set; } = false;
    public string JwtToken { get; set; }
    public string RefreshToken { get; set; }
}