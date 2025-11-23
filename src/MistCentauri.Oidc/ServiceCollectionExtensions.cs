using Microsoft.Extensions.DependencyInjection;

namespace MistCentauri.Oidc;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddOidc(this IServiceCollection services)
    {
        services.AddHttpClient();
        services.AddMemoryCache(o => o.SizeLimit = 256);
        services.AddSingleton<WellKnownDocumentCache>();
        services.AddSingleton<ChallengeCache>();
        services.AddSingleton<IWebDataProtector<StateProperties>, WebDataProtector<StateProperties>>();
        return services;
    }
}
