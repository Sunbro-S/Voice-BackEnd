using System.Text.Json;
using Domain.Models;
using MassTransit;
using RPC.Interface;
using Services.Services.Interfaces;

namespace RPC;

public class ProducerTestService : IProducerTestService
{
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly IAuthService _userService;

    public ProducerTestService(IPublishEndpoint publishEndpoint, IAuthService userService)
    {
        _publishEndpoint = publishEndpoint;
        _userService = userService;
    }

    public async Task SendTestMessageAsync(KafkaFriendshipRequest response)
    {
        await _publishEndpoint.Publish<KafkaFriendshipRequest>(response);
   }
}

