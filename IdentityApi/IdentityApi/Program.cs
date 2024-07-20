
using Infrastructure;
using Infrastructure.Data.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Services;
using System.Text;
using Domain.Models;

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
