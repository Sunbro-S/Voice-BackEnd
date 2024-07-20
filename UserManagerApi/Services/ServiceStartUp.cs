using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Services.Services;
using Services.Services.Interfaces;

namespace Services;

public static class ServiceStartUp
{
    public static IServiceCollection TryAddService(this IServiceCollection services)
    {
        services.TryAddScoped<IAuthService, AuthService>();
        return services;
    }
}