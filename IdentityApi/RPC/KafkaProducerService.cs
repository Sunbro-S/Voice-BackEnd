using IdentityApi.Models;
using MassTransit;
using RPC.Interface;

namespace RPC;

public class KafkaProducerService : IKafkaProducerService
{
    private readonly IPublishEndpoint _publishEndpoint;

    public KafkaProducerService(IPublishEndpoint publishEndpoint)
    {
        _publishEndpoint = publishEndpoint;
    }

    public async Task SendMessageAsync(KafkaFriendshipRequest request)
    {
        await _publishEndpoint.Publish(request);
    }
}