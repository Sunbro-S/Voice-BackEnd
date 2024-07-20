using Domain.Models;

namespace RPC.Interface;

public interface IKafkaProducerService
{
    Task SendMessageAsync(FriendshipResponse response);
}