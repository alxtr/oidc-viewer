using Microsoft.Extensions.Caching.Memory;

namespace MistCentauri.Oidc;

sealed internal class ChallengeCache
{
    private readonly IMemoryCache _cache;

    public ChallengeCache(IMemoryCache cache)
    {
        _cache = cache;
    }

    public void Store(string correlationId, ChallengeState state, TimeSpan validFor)
    {
        if (_cache.TryGetValue($"ch_{correlationId}", out _))
        {
            throw new Exception("Correlation id already exists");
        }

        var cacheEntryOptions = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = validFor,
            Size = 1
        };
        _cache.Set($"ch_{correlationId}", state, cacheEntryOptions);
    }

    public ChallengeState? Get(string correlationId)
    {
        return _cache.Get<ChallengeState>($"ch_{correlationId}");
    }

    public void Remove(string correlationId)
    {
        _cache.Remove(correlationId);
    }
}

sealed internal record ChallengeState(SignInRequest Request, string CodeVerifier);
