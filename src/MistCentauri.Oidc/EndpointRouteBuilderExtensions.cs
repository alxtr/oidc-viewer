using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;

namespace MistCentauri.Oidc;

public static class EndpointRouteBuilderExtensions
{
    private const string CodeVerifierProperty = "code_verifier";
    private const string CodeChallengeKey = "code_challenge";
    private const string CodeChallengeMethodKey = "code_challenge_method";

    private const string CorrelationCookiePrefix = "MistCentauri.Oidc.CorrelationId";
    private const string CorrelationProperty = "correlation_id";
    private const string CorrelationSentinel = "0";

    private const string RootPath = "/";
    private const string SignInPath = "/signin";
    private const string SignInCallbackPath = "/signin-callback";
    private const string SignOutPath = "/signout";

    // TODO: Options for redirect uri
    public static IEndpointRouteBuilder MapOidcEndpoints(this IEndpointRouteBuilder builder)
    {
        builder.MapPost(SignInPath, SignIn);
        builder.MapGet(SignInCallbackPath, SignInCallback);
        builder.MapPost(SignOutPath, async (HttpContext context) =>
        {
            await context.SignOutAsync();
            return Results.Redirect(RootPath);
        });

        return builder;
    }

    private async static Task<IResult> SignIn(
        HttpContext context, 
        IAntiforgery antiforgery, 
        WellKnownDocumentCache documentCache, 
        ChallengeCache challengeCache, 
        IWebDataProtector<StateProperties> protector, 
        [FromForm] SignInRequest signInRequest)
    {
        if (!await antiforgery.IsRequestValidAsync(context))
        {
            return Results.Redirect(RootPath);
        }

        WellKnownDocument? wellKnown = await documentCache.GetAsync(signInRequest.Authority);
        if (wellKnown == null)
        {
            return Results.BadRequest(".well-known not found");
        }

        string callbackUri = BuildRedirectUri(context.Request, SignInCallbackPath);

        var parameters = new Dictionary<string, string?>
        {
            { "client_id", signInRequest.ClientId },
            { "scope", signInRequest.Scope },
            { "response_type", "code" },
            { "redirect_uri", callbackUri }
        };

        var codeVerifier = GenerateBase64UrlRandom();
        var challengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        var codeChallenge = WebEncoders.Base64UrlEncode(challengeBytes);

        parameters[CodeChallengeKey] = codeChallenge;
        parameters[CodeChallengeMethodKey] = "S256";

        string correlationId = GenerateBase64UrlRandom();

        var cookieOptions = new CookieOptions()
        {
            HttpOnly = true,
            Secure = true,
            MaxAge = TimeSpan.FromMinutes(2)
        };
        context.Response.Cookies.Append($"{CorrelationCookiePrefix}.{correlationId}", CorrelationSentinel, cookieOptions);

        StateProperties state = new StateProperties()
        {
            { CorrelationProperty, correlationId },
            { CodeVerifierProperty, codeVerifier}
        };

        parameters["state"] = protector.Protect(state);

        var challenge = new ChallengeData(signInRequest, codeVerifier);
        challengeCache.Store(state[CorrelationProperty], challenge);

        var challengeUri = BuildChallengeUrl(wellKnown.AuthorizationEndpoint, parameters);
        return Results.Redirect(challengeUri);
    }

    private async static Task<IResult> SignInCallback(
        HttpContext context, 
        IHttpClientFactory factory, 
        WellKnownDocumentCache documentCache, 
        ChallengeCache challengeCache,
        IWebDataProtector<StateProperties> stateProtector,
        [FromQuery] string state, 
        [FromQuery] string code)
    {
        StateProperties? stateProperties = stateProtector.Unprotect(state);

        if (stateProperties is null)
        {
            return Results.BadRequest("Invalid state");
        }

        if (!stateProperties.TryGetValue(CorrelationProperty, out string? correlationId))
        {
            return Results.BadRequest("Invalid state");
        }

        string cookieName = $"{CorrelationCookiePrefix}.{correlationId}";
        
        if (!context.Request.Cookies.TryGetValue(cookieName, out string? correlationSentinel) || string.IsNullOrEmpty(correlationSentinel))
        {
            return Results.BadRequest("Invalid state");
        }

        context.Response.Cookies.Delete(cookieName);

        if (!string.Equals(correlationSentinel, CorrelationSentinel, StringComparison.InvariantCulture))
        {
            return Results.BadRequest("Invalid correlation id");
        }

        ChallengeData? challenge = challengeCache.Get(correlationId);
        challengeCache.Remove(correlationId);

        if (challenge is null)
        {
            return Results.BadRequest("Invalid state");
        }

        WellKnownDocument? wellKnown = await documentCache.GetAsync(challenge.Request.Authority);
        if (wellKnown == null)
        {
            return Results.BadRequest(".well-known not found");
        }
        
        string redirectUri = BuildRedirectUri(context.Request, SignInCallbackPath);
        
        var request = new HttpRequestMessage(HttpMethod.Post, wellKnown.TokenEndpoint);

        request.Content = new FormUrlEncodedContent([
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("code", code),
            new KeyValuePair<string, string>("redirect_uri", redirectUri),
            new KeyValuePair<string, string>("client_id", challenge.Request.ClientId),
            new KeyValuePair<string, string>("client_secret", challenge.Request.ClientSecret),
            new KeyValuePair<string, string>("code_verifier", challenge.CodeVerifier)
        ]);

        var client = factory.CreateClient();
        var response = await client.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
            // TODO: Read 400s correctly /w error
            return Results.Content(await response.Content.ReadAsStringAsync(), statusCode: (int)response.StatusCode);
        }

        TokenResponse? tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();

        if (tokenResponse is null)
        {
            // TODO: Include ?error=
            return Results.Redirect(RootPath);
        }

        var properties = new AuthenticationProperties();
        properties.StoreTokens([
            new AuthenticationToken()
            {
                Name = "access_token",
               Value = tokenResponse.AccessToken
            },
            new AuthenticationToken()
            {
                Name = "refresh_token",
                Value = tokenResponse.RefreshToken
            },
            new AuthenticationToken()
            {
                Name = "token_type",
                Value = tokenResponse.TokenType
            },
            new AuthenticationToken()
            {
                Name = "scope",
                Value = tokenResponse.Scope
            },
            new AuthenticationToken()
            {
                Name = "expires_in",
                Value = tokenResponse.ExpiresIn
            }
        ]);

        // TODO: Add metadata to properties
        // TODO: Map basic claims

        List<Claim> claims = [
            new Claim("your-claim", "your-value")
        ];

        // TODO: Change auth type name
        await context.SignInAsync(new ClaimsPrincipal(new ClaimsIdentity(claims, "oidc")), properties);
        return Results.Redirect(RootPath);
    }

    private static string BuildChallengeUrl(Uri authorizationEndpoint, Dictionary<string, string?> parameters)
        => QueryHelpers.AddQueryString(authorizationEndpoint.ToString(), parameters);
    
    private static string BuildRedirectUri(HttpRequest request, string targetPath)
        => request.Scheme + Uri.SchemeDelimiter + request.Host + targetPath;

    private static string GenerateBase64UrlRandom()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return WebEncoders.Base64UrlEncode(bytes);
    }
}

sealed internal class StateProperties : Dictionary<string, string>;
