using Confluent.Kafka;
using Infrastructure;
using Infrastructure.Data.Models;
using MassTransit;
using MassTransit.KafkaIntegration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Services;
using System.Text;
using IdentityApi.Models;
using RPC;
using RPC.Interface;

var builder = WebApplication.CreateBuilder(args);


// Add services to the container.      
builder.Services.AddDbContext<ContextDb>(options =>
{
    options.UseNpgsql(builder.Configuration.GetSection("ConnectionStrings:DefaultConnection").Value,
        b => b.MigrationsAssembly("IdentityApi"));
});

builder.Services.AddIdentity<ExtendedIdentityUser, IdentityRole>(options =>
    {
        options.User.RequireUniqueEmail = true;
    options.Password.RequiredLength = 5;
}).AddEntityFrameworkStores<ContextDb>()
    .AddDefaultTokenProviders();

builder.Services.TryAddService();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
   .AddJwtBearer(options =>
   {
       // Настройка параметров валидации токена
       options.TokenValidationParameters = new TokenValidationParameters()
       {
           ValidateActor = false,
           ValidateIssuer = false,
           ValidateAudience = false,
           RequireExpirationTime = true,
           ValidateIssuerSigningKey = true,
           IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration.GetSection("Jwt:Key").Value)),
       };
   });

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
        rider.AddProducer<KafkaFriendshipRequest>("friendship-request-topic");

        rider.AddConsumer<KafkaFriendshipRequestConsumer>();

        rider.UsingKafka((context, k) =>
        {
            k.Host("kafka:9001");

            k.TopicEndpoint<KafkaFriendshipRequest>("friendship-request-topic", "groupid", c =>
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
    context.Database.Migrate();
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
