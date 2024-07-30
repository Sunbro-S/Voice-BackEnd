using System.Text.Json;
using Domain.Models;
using MassTransit;
using Microsoft.Extensions.Logging;
using RPC.Interface;
using Services.Services.Interfaces;

namespace RPC;

public class KafkaProducerService : IKafkaProducerService
{
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly IAuthService _userService;
    private readonly IBus _bus;
    private readonly ILogger<KafkaProducerService> _logger;

    public KafkaProducerService(IPublishEndpoint publishEndpoint, IAuthService userService, IBus bus, ILogger<KafkaProducerService> logger)
    {
        _publishEndpoint = publishEndpoint;
        _userService = userService;
        _bus = bus;
        _logger = logger;
    }

    public async Task SendMessageAsync(FriendshipResponse response)
    {
        _logger.LogInformation("Sending message: {@Response}", response);
        await _publishEndpoint.Publish<FriendshipResponse>(response);
        _logger.LogInformation("Message sent: {@Response}", response);
    }
}