using Domain.Models;

namespace RPC.Interface;

public interface IProducerTestService
{
    Task SendTestMessageAsync(KafkaFriendshipRequest response);
}