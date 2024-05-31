﻿namespace IdentityApi.Models;

public class RegisterRequest
{
    
    public string UserName { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }
    public string FullName { get; set; }

    /// <summary>
    /// List of RoleNames, comma delimited
    /// </summary>
    public string RolesCommaDelimited { get; set; }
}