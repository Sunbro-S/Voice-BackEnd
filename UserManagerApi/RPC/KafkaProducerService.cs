using Domain.Models;
using MassTransit;
using RPC.Interface;
using Services.Services.Interfaces;

namespace RPC;

public class KafkaProducerService : IKafkaProducerService
{
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly IAuthService _userService;

    public KafkaProducerService(IPublishEndpoint publishEndpoint, IAuthService userService)
    {
        _publishEndpoint = publishEndpoint;
        _userService = userService;
    }

    public async Task SendMessageAsync(FriendshipResponse response)
    {
        await _publishEndpoint.Publish(response);
    }
}