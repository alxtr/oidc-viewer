using Microsoft.Extensions.DependencyInjection;

namespace MistCentauri.Oidc;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddOidc(this IServiceCollection services, Action<OidcOptions>? configure = null)
    {
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.AddHttpClient();
        services.AddMemoryCache(o => o.SizeLimit = 256);
        services.AddSingleton<WellKnownDocumentCache>();
        services.AddSingleton<ChallengeCache>();
        services.AddSingleton<IRandomGenerator, UriSafeBase64RandomGenerator>();
        services.AddSingleton<IWebDataProtector<StateProperties>, WebDataProtector<StateProperties>>();
        services.AddSingleton<IWebDataProtector<string>, WebDataProtector<string>>();
        return services;
    }
}
