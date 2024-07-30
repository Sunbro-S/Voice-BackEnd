using Confluent.Kafka;
using Infrastructure;
using MassTransit;
using MassTransit.KafkaIntegration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Identity;
using RPC;
using RPC.Interface;
using Services;
using Domain.Models;
using Infrastructure.Data.Models;
using UserManagerApi;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<ContextDb>(options =>
{
    options.UseNpgsql(builder.Configuration.GetSection("ConnectionStrings:DefaultConnection").Value,
        b => b.MigrationsAssembly("UserManagerApi"));
});

builder.Services.AddIdentity<ExtendedIdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ContextDb>()
    .AddDefaultTokenProviders();

builder.Services.TryAddService();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllOrigins",
        builder => builder
            .AllowAnyOrigin()
            .AllowAnyHeader()
            .AllowAnyMethod()
            .WithExposedHeaders("X-Total-Count"));
});

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddMassTransit(x =>
{
    x.AddConsumer<KafkaFriendshipRequestConsumer>();
    x.AddConsumer<KafkaResponseConsumer>();

    x.UsingInMemory((context, cfg) =>
    {
        cfg.ConfigureEndpoints(context);
    });

    x.AddRider(rider =>
    {
        rider.AddProducer<FriendshipResponse>("friendship-response-topic");
        rider.AddProducer<KafkaFriendshipRequest>("friendship-request-topic");
        rider.AddConsumer<KafkaFriendshipRequestConsumer>();
        rider.AddConsumer<KafkaResponseConsumer>();
        
        // Configure Kafka using the options

        rider.UsingKafka((context, k) =>
        {
            k.Host("kafka:9001");

            k.TopicEndpoint<KafkaFriendshipRequest>("friendship-request-topic", "group_id", c =>
            {
                c.ConfigureConsumer<KafkaFriendshipRequestConsumer>(context);
            });
            k.TopicEndpoint<FriendshipResponse>("friendship-response-topic", "group_id", c =>
            {
                c.ConfigureConsumer<KafkaResponseConsumer>(context);
            });
        });
    });
});

builder.Services.AddMassTransitHostedService();
builder.Services.AddScoped<IProducerTestService, ProducerTestService>();
builder.Services.AddScoped<IKafkaProducerService, KafkaProducerService>();
builder.Services.AddScoped<KafkaFriendshipRequestConsumer>();
builder.Services.AddScoped<KafkaResponseConsumer>();

var app = builder.Build();
app.UseCors("AllowAllOrigins");

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<ContextDb>();

    try
    {
        if (context.Database.GetPendingMigrations().Any())
        {
            context.Database.Migrate();
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"An error occurred while migrating the database: {ex.Message}");
    }
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
