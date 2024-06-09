using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Infrastructure;
using Infrastructure.Data.Models;
using Services;

var builder = WebApplication.CreateBuilder(args);


// Add services to the container.      
builder.Services.AddDbContext<ContextDb>(options =>
{
    options.UseNpgsql(builder.Configuration.GetSection("ConnectionStrings:DefaultConnection").Value,
        b => b.MigrationsAssembly("IdentityApi"));
});

builder.Services.AddIdentity<ExtendedIdentityUser, IdentityRole>(options =>
{
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


builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();
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
