using System.Text.Json.Serialization;

namespace Domain.Models;

public class FriendshipResponse
{
    [JsonPropertyName("Result")]
    public bool Result { get; set; }

    [JsonPropertyName("Description")]
    public string Description { get; set; }

    public FriendshipResponse(bool result, string description)
    {
        Result = result;
        Description = description;
    }

    public FriendshipResponse() { }
}