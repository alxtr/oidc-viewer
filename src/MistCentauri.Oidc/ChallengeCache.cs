using Microsoft.Extensions.Caching.Memory;

namespace MistCentauri.Oidc;

internal class ChallengeCache
{
    private readonly IMemoryCache _cache;

    public ChallengeCache(IMemoryCache cache)
    {
        _cache = cache;
    }

    public void Store(string correlationId, ChallengeData data)
    {
        if (_cache.TryGetValue(correlationId, out _))
        {
            throw new Exception();
        }
        var cacheEntryOptions = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15),
            Size = 1
        };
        _cache.Set(correlationId, data, cacheEntryOptions);
    }

    public ChallengeData? Get(string correlationId)
    {
        _cache.TryGetValue(correlationId, out ChallengeData? value);
        return value;
    }
}

internal record ChallengeData(string Authority, string ClientId, string ClientSecret, string CodeVerifier);
