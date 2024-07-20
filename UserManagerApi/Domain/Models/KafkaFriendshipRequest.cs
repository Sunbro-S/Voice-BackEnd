namespace Domain.Models;

public class KafkaFriendshipRequest
{
    
    public string User { get; set; }
    public string Friend { get; set; }
    public string Type { get; set; }
}