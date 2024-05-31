using System.ComponentModel.DataAnnotations;

namespace Infrastructure.Data.Models;

public class UserEntity
{
    [Key]
    public string UserId { get; set; }
    public string UserName { get; set; }
    public string Mail { get; set; }
    public string? Name { get; set; }
    public string? Lastname { get; set; }
    public string? Otchestvo { get; set; }
    public string? OpenedRooms { get; set; }
    public string? CreatedRooms { get; set; } = null;
    public string? Icon { get;set; } = null;
}