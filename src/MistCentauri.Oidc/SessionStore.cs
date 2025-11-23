using Microsoft.Extensions.Caching.Memory;

namespace MistCentauri.Oidc;

internal interface ISessionStore
{
    string Create(TimeSpan expiresIn);

    void Set(string sessionId, string key, object? value);

    void Destroy(string sessionId);
}

sealed internal class InMemorySessionStore : ISessionStore
{
    private readonly IMemoryCache _cache;

    public InMemorySessionStore(IMemoryCache cache)
    {
        _cache = cache;
    }

    public string Create(TimeSpan expiresIn)
    {
        string sessionId = Guid.NewGuid().ToString();

        if (_cache.TryGetValue($"ses_{sessionId}", out _))
        {
            throw new InvalidOperationException("Session already exists");
        }

        var cacheEntryOptions = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = expiresIn,
            Size = 1
        };
        _cache.Set($"ses_{sessionId}", new Dictionary<string, object?>(), cacheEntryOptions);

        return sessionId;
    }

    public void Set(string sessionId, string key, object? value)
    {
        if (!_cache.TryGetValue($"ses_{sessionId}", out Dictionary<string, object?>? session) || session is null)
        {
            throw new Exception("Session not found");
        }

        session[key] = value;
    }

    public void Destroy(string sessionId)
    {
        _cache.Remove(sessionId);
    }
}
