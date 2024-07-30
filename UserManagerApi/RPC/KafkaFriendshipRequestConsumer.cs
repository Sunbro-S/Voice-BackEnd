using Domain.Models;
using MassTransit;
using Microsoft.Extensions.Logging;
using RPC.Interface;
using Services.Services.Interfaces;

namespace RPC;

public class KafkaFriendshipRequestConsumer : IConsumer<KafkaFriendshipRequest>
{
    private readonly ILogger<KafkaFriendshipRequestConsumer> _logger;

    private readonly IKafkaProducerService _producerService;
    private readonly IAuthService _userService;

    public KafkaFriendshipRequestConsumer(ILogger<KafkaFriendshipRequestConsumer> logger, IAuthService userService,
        IKafkaProducerService producerService)
    {
        _logger = logger;
        _userService = userService;
        _producerService = producerService;
    }

    public async Task Consume(ConsumeContext<KafkaFriendshipRequest> context)
    {
        var message = context.Message;
        _logger.LogInformation($"Received message: Type={message.Type}, User={message.User}, Friend={message.Friend}");
        var res = await _userService.AddFriendAsync(message.User, message.Friend);
        if (res.Item1)
        {
            _logger.LogInformation($"отправляю пользователя:{res.Item2}, добавил:{res.Item3}");
            var response = new FriendshipResponse
            {
                Result = true,
                Description = "All good"
            };
            await _producerService.SendMessageAsync(response);
        }
        else
        {
            var response = new FriendshipResponse
            {
                Result = false,
                Description = "Something went worng"
            };
            await _producerService.SendMessageAsync(response);
        }
    }
}