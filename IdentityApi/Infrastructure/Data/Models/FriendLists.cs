using Microsoft.Build.Framework;

namespace Infrastructure.Data.Models;

public class FriendLists
{
    [Required]
    public string Id { get; set; }

    public required List<string> FriendList { get; set; }
}