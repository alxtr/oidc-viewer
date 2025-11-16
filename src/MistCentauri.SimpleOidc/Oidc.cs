using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

namespace MistCentauri.SimpleOidc;

public static class Oidc
{
    private const string RootPath = "/";
    private const string SignInPath = "/signin";
    private const string CallbackPath = "/signin-callback";

    public static IServiceCollection AddOidc(this IServiceCollection services)
    {
        services.AddHttpClient();
        services.AddMemoryCache();

        services.AddSingleton<WellKnownCache>();
        services.AddSingleton<ChallengeCache>();
        
        return services;
    }
    
    public static IEndpointRouteBuilder MapOidc(this IEndpointRouteBuilder builder)
    {
        builder.MapPost(SignInPath, async (HttpContext context, IAntiforgery antiforgery, WellKnownCache wellKnownCache, ChallengeCache challengeCache, [FromForm] SignInFormPost formPost) =>
        {
            if (!await antiforgery.IsRequestValidAsync(context))
            {
                return Results.Redirect(RootPath);
            }
            
            // Get .well-known document
            WellKnownDocument? wellKnown = await wellKnownCache.GetAsync(formPost.Authority);
            if (wellKnown == null)
            {
                return Results.BadRequest(".well-known not found");
            }

            // Create redirect uri from form post
            string callbackUri = BuildRedirectUri(context.Request, CallbackPath);
            string challengeUri = BuildChallengeUrl(wellKnown.AuthorizationEnpoint, formPost, callbackUri, challengeCache);
            
            // Redirect to challenge
            return Results.Redirect(challengeUri);
        });

        builder.MapGet(CallbackPath, async (HttpContext context, IHttpClientFactory factory, WellKnownCache wellKnownCache, ChallengeCache challengeCache) =>
        {
            string state = context.Request.Query["state"].ToString(); 
            string code = context.Request.Query["code"].ToString();

            ChallengeEntry challenge = challengeCache.Get(state);

            WellKnownDocument? wellKnown = await wellKnownCache.GetAsync(challenge.Authority);
            if (wellKnown == null)
            {
                return Results.BadRequest(".well-known not found");
            }
            
            string redirectUri = BuildRedirectUri(context.Request, CallbackPath);
            
            var request = new HttpRequestMessage(HttpMethod.Post, wellKnown.TokenEndpoint);

            string credentials = ToBase64($"{challenge.ClientId}:{challenge.ClientSecret}");
            request.Headers.Add("Authorization", $"Basic {credentials}");
            
            request.Content = new FormUrlEncodedContent([
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("redirect_uri", redirectUri),
                new KeyValuePair<string, string>("client_id", challenge.ClientId),
                new KeyValuePair<string, string>("code_verifier", challenge.CodeVerifier)
            ]);

            var client = factory.CreateClient();
            var response = await client.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                return Results.Content(await response.Content.ReadAsStringAsync(), statusCode: (int)response.StatusCode);
            }

            UserToken? token = await response.Content.ReadFromJsonAsync<UserToken>();
            
            string rootUri = BuildRedirectUri(context.Request, RootPath);
            rootUri = QueryHelpers.AddQueryString(rootUri, [ new KeyValuePair<string, StringValues>("token", token?.AccessToken)]);
            return Results.Redirect(rootUri);
        });

        return builder;
    }
    
    private static string BuildChallengeUrl(Uri authorizationEndpoint, SignInFormPost properties, string redirectUri, ChallengeCache challengeCache)
    {
        string correlationId = Guid.NewGuid().ToString();
        
        var parameters = new Dictionary<string, string?>
        {
            { "client_id", properties.ClientId },
            { "scope", properties.Scopes },
            { "response_type", "code" },
            { "redirect_uri", redirectUri },
            { "state", correlationId } // Needs to be more secure
        };

        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        var codeVerifier = Base64UrlTextEncoder.Encode(bytes);

        var challengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        var codeChallenge = WebEncoders.Base64UrlEncode(challengeBytes);

        parameters[OAuthConstants.CodeChallengeKey] = codeChallenge;
        parameters[OAuthConstants.CodeChallengeMethodKey] = OAuthConstants.CodeChallengeMethodS256;
        
        // Store this for use during the code redemption.
        challengeCache.Add(correlationId, properties.Authority, properties.ClientId, properties.ClientSecret, codeVerifier);
        
        return QueryHelpers.AddQueryString(authorizationEndpoint.ToString(), parameters);
    }
    
    private static string BuildRedirectUri(HttpRequest request, string targetPath)
        => request.Scheme + Uri.SchemeDelimiter + request.Host + targetPath;
    
    private static string ToBase64(string text) 
    {
        var plainTextBytes = Encoding.UTF8.GetBytes(text);
        return Convert.ToBase64String(plainTextBytes);
    }
}

public class WellKnownDocument
{
    [JsonPropertyName("authorization_endpoint")]
    public Uri AuthorizationEnpoint { get; set; }
    
    [JsonPropertyName("token_endpoint")]
    public Uri TokenEndpoint { get; set; }
}

public class SignInFormPost
{
    public string Authority { get; set; }
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
    public string Scopes { get; set; }
}

public class WellKnownCache
{
    private const string WellKnown = ".well-known/openid-configuration";

    private readonly IMemoryCache _cache;
    private readonly IHttpClientFactory _clientFactory;

    public WellKnownCache(IMemoryCache cache, IHttpClientFactory clientFactory)
    {
        _cache = cache;
        _clientFactory = clientFactory;
    }

    public async Task<WellKnownDocument?> GetAsync(string authority)
    {
        if (!_cache.TryGetValue(authority, out WellKnownDocument? wellKnownDocument))
        {
            HttpClient client = _clientFactory.CreateClient();
            Uri wellKnowUri = new Uri(new Uri(authority), WellKnown);
            wellKnownDocument = await client.GetFromJsonAsync<WellKnownDocument>(wellKnowUri);
            
            var cacheEntryOptions = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(24),
                Size = 1
            };
            _cache.Set(authority, wellKnownDocument, cacheEntryOptions);
        }

        return wellKnownDocument;
    }
}

public class ChallengeCache
{
    private readonly IMemoryCache _cache;

    public ChallengeCache(IMemoryCache cache)
    {
        _cache = cache;
    }

    public void Add(string correlationId, string authority, string clientId, string clientSecret, string codeVerifier)
    {
        if (_cache.TryGetValue(correlationId, out _))
            throw new Exception("Correlation already used");
        
        var cacheEntryOptions = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1), // Review
            Size = 1
        };
        _cache.Set(correlationId, new ChallengeEntry(authority, clientId, clientSecret, codeVerifier),  cacheEntryOptions);
    }
    
    public ChallengeEntry Get(string correlationId)
    {
        if (!_cache.TryGetValue(correlationId, out ChallengeEntry? value) || value is null)
            throw new Exception("Invalid correlation id");
        
        return value;
    }
}

public record ChallengeEntry(string Authority, string ClientId, string ClientSecret, string CodeVerifier);

public class UserToken
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }
}
