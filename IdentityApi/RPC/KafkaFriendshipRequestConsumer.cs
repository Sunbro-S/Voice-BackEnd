using IdentityApi.Models;
using MassTransit;
using Microsoft.Extensions.Logging;

namespace RPC;

public class KafkaFriendshipRequestConsumer: IConsumer<KafkaFriendshipRequest>
{
    private readonly ILogger<KafkaFriendshipRequestConsumer> _logger;

    public KafkaFriendshipRequestConsumer(ILogger<KafkaFriendshipRequestConsumer> logger)
    {
        _logger = logger;
    }

    public async Task Consume(ConsumeContext<KafkaFriendshipRequest> context)
    {
        var message = context.Message;
        _logger.LogInformation($"Received message: Type={message.Type}, User={message.User}, Friend={message.Friend}");

    }
}