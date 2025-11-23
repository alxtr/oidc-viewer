using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Caching.Memory;

namespace MistCentauri.Oidc;

sealed internal class WellKnownDocumentCache
{
    private const string WellKnown = ".well-known/openid-configuration";

    private readonly IMemoryCache _cache;
    private readonly IHttpClientFactory _clientFactory;

    public WellKnownDocumentCache(IMemoryCache cache, IHttpClientFactory clientFactory)
    {
        _cache = cache;
        _clientFactory = clientFactory;
    }

    public async Task<WellKnownDocument?> GetAsync(string authority)
    {
        if (!_cache.TryGetValue($"aut_{UriBase64.Encode(authority)}", out WellKnownDocument? wellKnownDocument))
        {
            HttpClient client = _clientFactory.CreateClient();
            Uri wellKnowUri = new Uri(new Uri(authority), WellKnown);

            wellKnownDocument = await client.GetFromJsonAsync<WellKnownDocument>(wellKnowUri);
            
            var cacheEntryOptions = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(24),
                Size = 1
            };
            _cache.Set($"aut_{UriBase64.Encode(authority)}", wellKnownDocument, cacheEntryOptions);
        }

        return wellKnownDocument;
    }
}

sealed internal class WellKnownDocument
{
    [JsonPropertyName("authorization_endpoint")]
    public Uri AuthorizationEndpoint { get; set; }
    
    [JsonPropertyName("token_endpoint")]
    public Uri TokenEndpoint { get; set; }
    
    [JsonPropertyName("end_session_endpoint")]
    public Uri SignoutEndpoint { get; set; }
}
