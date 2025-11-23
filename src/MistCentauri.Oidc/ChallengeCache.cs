using Microsoft.Extensions.Caching.Memory;

namespace MistCentauri.Oidc;

sealed internal class ChallengeCache
{
    private readonly IMemoryCache _cache;

    public ChallengeCache(IMemoryCache cache)
    {
        _cache = cache;
    }

    public void Store(string correlationId, ChallengeData data)
    {
        if (_cache.TryGetValue($"ch_{correlationId}", out _))
        {
            throw new Exception();
        }
        var cacheEntryOptions = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(2),
            Size = 1
        };
        _cache.Set($"ch_{correlationId}", data, cacheEntryOptions);
    }

    public ChallengeData? Get(string correlationId)
    {
        _cache.TryGetValue($"ch_{correlationId}", out ChallengeData? value);
        return value;
    }

    public void Remove(string correlationId)
    {
        _cache.Remove(correlationId);
    }
}

internal record ChallengeData(SignInRequest Request, string CodeVerifier);
