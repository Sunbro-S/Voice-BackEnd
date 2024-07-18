namespace IdentityApi.Models;

public class KafkaFriendshipRequest
{
    public string Type { get; set; }
    public string User { get; set; }
    public string Friend { get; set; }
}