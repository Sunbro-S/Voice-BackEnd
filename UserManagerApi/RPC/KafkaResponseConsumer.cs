using Domain.Models;
using MassTransit;
using Microsoft.Extensions.Logging;
using RPC.Interface;
using Services.Services.Interfaces;

namespace RPC;

public class KafkaResponseConsumer : IConsumer<FriendshipResponse>
{
    private readonly ILogger<KafkaResponseConsumer> _logger;

    private readonly IKafkaProducerService _producerService;
    private readonly IAuthService _userService;

    public KafkaResponseConsumer(ILogger<KafkaResponseConsumer> logger, IAuthService userService,
        IKafkaProducerService producerService)
    {
        _logger = logger;
        _userService = userService;
        _producerService = producerService;
    }


    public async Task Consume(ConsumeContext<FriendshipResponse> context)
    {
        var message = context.Message;
        _logger.LogInformation($"Received message: Result={message.Result}, Description={message.Description}");
    }
}