namespace IdentityApi.Models;

public class LoginResponse
{
    public Tokens Tokens { get; set; }
    public User User { get; set; }
}

public class Tokens
{
    public bool IsLogedIn { get; set; } = false;
    public string? JwtToken { get; set; }
    public long? JwtTokenExpiry { get; set; }
    public string? RefreshToken { get; set; }
}

public class User
{
    public string Login { get; set; }
    public string Fullname { get; set; }
    public string Email { get; set; }
}
