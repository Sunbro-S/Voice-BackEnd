using Confluent.Kafka;
using Infrastructure;
using MassTransit;
using MassTransit.KafkaIntegration;
using Microsoft.EntityFrameworkCore;
using Services;
using Domain.Models;
using Infrastructure.Data.Models;
using Microsoft.AspNetCore.Identity;
using RPC;
using RPC.Interface;
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
            .AllowAnyMethod());
});

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddMassTransit(x =>
{
    x.AddConsumer<KafkaFriendshipRequestConsumer>();

    x.UsingInMemory((context, cfg) =>
    {
        cfg.ConfigureEndpoints(context);
    });

    x.AddRider(rider =>
    {
        rider.AddProducer<FriendshipResponse>("friendship-response-topic");

        rider.AddConsumer<KafkaFriendshipRequestConsumer>();
        rider.UsingKafka((context, k) =>
        {
            k.Host("kafka:9001");

            k.TopicEndpoint<KafkaFriendshipRequest>("friendship-request-topic", "group_id", c =>
            {
                c.ConfigureConsumer<KafkaFriendshipRequestConsumer>(context);
            });
        });
    });
});

builder.Services.AddMassTransitHostedService();
builder.Services.AddScoped<IKafkaProducerService, KafkaProducerService>();
builder.Services.AddScoped<KafkaFriendshipRequestConsumer>();


var app = builder.Build();
app.UseCors("AllowAllOrigins");
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<ContextDb>();

    try
    {
        // Применить миграции только если есть новые миграции
        if (context.Database.GetPendingMigrations().Any())
        {
            context.Database.Migrate();
        }
    }
    catch (Exception ex)
    {
        // Обработка ошибки
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
