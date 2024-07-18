using IdentityApi.Models;

namespace RPC.Interface;

public interface IKafkaProducerService
{
    Task SendMessageAsync(KafkaFriendshipRequest request);
}