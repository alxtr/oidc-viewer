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
using Microsoft.Extensions.Options;

namespace MistCentauri.Oidc;

public static class EndpointRouteBuilderExtensions
{
    private const string AuthenticationType = "mist-centauri-oidc";
    
    private const string CodeVerifierProperty = "code_verifier";
    private const string CodeChallengeKey = "code_challenge";
    private const string CodeChallengeMethodKey = "code_challenge_method";

    private const string CorrelationCookiePrefix = "MistCentauri.Oidc.CorrelationId";
    private const string CorrelationProperty = "correlation_id";
    private const string CorrelationSentinel = "0";

    private const string SignInPath = "/signin";
    private const string SignInCallbackPath = "/signin-callback";
    private const string SignOutPath = "/signout";

    public static IEndpointRouteBuilder MapOidcEndpoints(this IEndpointRouteBuilder builder)
    {
        builder.MapPost(SignInPath, SignIn);
        builder.MapGet(SignInCallbackPath, SignInCallback);
        builder.MapPost(SignOutPath, SignOut);
        builder.MapGet(SignOutPath, SignOut);
        return builder;
    }

    private async static Task<IResult> SignIn(
        HttpContext context, 
        IOptions<OidcOptions> options,
        IAntiforgery antiforgery, 
        WellKnownDocumentCache documentCache, 
        ChallengeCache challengeCache,
        IRandomGenerator random,
        IWebDataProtector<StateProperties> protector, 
        [FromForm] SignInRequest signInRequest)
    {
        if (!await antiforgery.IsRequestValidAsync(context))
        {
            return ErrorRedirect(context.Request, options.Value.ErrorRedirect, "invalid_csrf_token");
        }

        WellKnownDocument? wellKnown = await documentCache.GetAsync(signInRequest.Authority);
        if (wellKnown == null)
        {
            return ErrorRedirect(context.Request, options.Value.ErrorRedirect, "discovery_document_not_found");
        }

        string callbackUri = BuildRedirectUri(context.Request, SignInCallbackPath);

        var parameters = new Dictionary<string, string?>
        {
            { "client_id", signInRequest.ClientId },
            { "scope", signInRequest.Scope },
            { "response_type", "code" },
            { "redirect_uri", callbackUri }
        };

        var codeVerifier = random.Generate();
        var challengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        var codeChallenge = WebEncoders.Base64UrlEncode(challengeBytes);

        parameters[CodeChallengeKey] = codeChallenge;
        parameters[CodeChallengeMethodKey] = "S256";

        string correlationId = random.Generate();

        var cookieOptions = new CookieOptions()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            IsEssential = true,
            MaxAge = options.Value.ChallengeTimeout
        };
        context.Response.Cookies.Append($"{CorrelationCookiePrefix}.{correlationId}", CorrelationSentinel, cookieOptions);

        StateProperties state = new StateProperties()
        {
            { CorrelationProperty, correlationId },
            { CodeVerifierProperty, codeVerifier}
        };

        parameters["state"] = protector.Protect(state);

        var challenge = new ChallengeState(signInRequest, codeVerifier);
        challengeCache.Store(state[CorrelationProperty], challenge, options.Value.ChallengeTimeout);

        var challengeUri = QueryHelpers.AddQueryString(wellKnown.AuthorizationEndpoint.ToString(), parameters);
        return Results.Redirect(challengeUri);
    }

    private async static Task<IResult> SignInCallback(
        HttpContext context,
        IOptions<OidcOptions> options,
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
            return ErrorRedirect(context.Request, options.Value.ErrorRedirect, "state_invalid_or_not_found");
        }

        if (!stateProperties.TryGetValue(CorrelationProperty, out string? correlationId))
        {
            return ErrorRedirect(context.Request, options.Value.ErrorRedirect, "state_correlation_id_not_found");
        }

        string cookieName = $"{CorrelationCookiePrefix}.{correlationId}";
        
        if (!context.Request.Cookies.TryGetValue(cookieName, out string? correlationSentinel) || string.IsNullOrEmpty(correlationSentinel))
        {
            return ErrorRedirect(context.Request, options.Value.ErrorRedirect, "correlation_cookie_invalid_or_not_found");
        }

        context.Response.Cookies.Delete(cookieName);

        if (!string.Equals(correlationSentinel, CorrelationSentinel, StringComparison.InvariantCulture))
        {
            return ErrorRedirect(context.Request, options.Value.ErrorRedirect, "invalid_correlation_id");
        }

        string? error = context.Request.Query["error"];
        if (!string.IsNullOrWhiteSpace(error))
        {
            return ErrorRedirect(context.Request, options.Value.ErrorRedirect, error);
        }
    
        ChallengeState? challenge = challengeCache.Get(correlationId);
        challengeCache.Remove(correlationId);

        if (challenge is null)
        {
            return ErrorRedirect(context.Request, options.Value.ErrorRedirect, "challenge_state_not_found");
        }

        WellKnownDocument? wellKnown = await documentCache.GetAsync(challenge.Request.Authority);
        if (wellKnown == null)
        {
            return ErrorRedirect(context.Request, options.Value.ErrorRedirect, "discovery_document_not_found");
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
            TokenErrorResponse? errorResponse = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
            return ErrorRedirect(
                context.Request, 
                options.Value.ErrorRedirect, 
                errorResponse?.Error ?? "unexpected_error", 
                errorResponse?.ErrorDescription);
        }

        TokenResponse? tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();

        if (tokenResponse is null)
        {
            return ErrorRedirect(context.Request, options.Value.ErrorRedirect, "invalid_token_response");
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
                Value = tokenResponse.ExpiresIn.ToString()
            }
        ]);

        // Store useful metadata
        properties.Items.Add("authority", challenge.Request.Authority);
        properties.Items.Add("client_id", challenge.Request.ClientId);
        properties.Items.Add("client_secret", challenge.Request.ClientSecret);
        properties.Items.Add("scope", challenge.Request.Scope);

        var claims = await EnumerateClaimsAsync(client, wellKnown.UserInfoEndpoint, tokenResponse.AccessToken);
        if (claims.Count == 0)
        {
            return ErrorRedirect(context.Request, options.Value.ErrorRedirect, "invalid_user_info");
        }

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, AuthenticationType));

        await context.SignInAsync(principal, properties);
        return Results.Redirect(options.Value.SignInRedirect);
    }

    private async static Task<IResult> SignOut(
        HttpContext context,
        IOptions<OidcOptions> options,
        IHttpClientFactory factory, 
        WellKnownDocumentCache documentCache)
    {
        AuthenticateResult ticket = await context.AuthenticateAsync();
        if (!ticket.Succeeded)
        {
            return Results.Redirect(options.Value.SignOutRedirect);
        }

        await context.SignOutAsync();

        string? authority = ticket.Properties.Items["authority"];
        if (string.IsNullOrEmpty(authority))
        {
            return Results.Redirect(options.Value.SignOutRedirect);
        }

        WellKnownDocument? wellKnown = await documentCache.GetAsync(authority);
        if (wellKnown == null)
        {
            return ErrorRedirect(context.Request, options.Value.ErrorRedirect, "discovery_document_not_found");
        }

        if (wellKnown.SignoutEndpoint is null)
        {
            return Results.Redirect(options.Value.SignOutRedirect);
        }

        string callbackUri = BuildRedirectUri(context.Request, options.Value.SignOutRedirect);
        
        var parameters = new Dictionary<string, string?>
        {
            { "post_logout_redirect_uri", callbackUri }
        };

        string redirectUri = QueryHelpers.AddQueryString(wellKnown.SignoutEndpoint.ToString(), parameters);
        return Results.Redirect(redirectUri);
    }

    private static string BuildRedirectUri(HttpRequest request, string targetPath)
        => request.Scheme + Uri.SchemeDelimiter + request.Host + targetPath;

    private static string BuildErrorUri(HttpRequest request, string path, string error, string? errorDescription = null)
    {
        string baseRedirectUri = BuildRedirectUri(request, path);

        var parameters = new Dictionary<string, string?>
        {
            { "error", UriBase64.Encode(error) }
        };

        if (!string.IsNullOrWhiteSpace(errorDescription))
        {
            parameters["error_description"] = UriBase64.Encode(errorDescription);
        }

        return QueryHelpers.AddQueryString(baseRedirectUri, parameters);
    }

    private static IResult ErrorRedirect(HttpRequest request, string path, string error, string? errorDescription = null)
    {
        string errorUri = BuildErrorUri(request, path, error, errorDescription);
        return Results.Redirect(errorUri);
    }

    private async static Task<IReadOnlyList<Claim>> EnumerateClaimsAsync(HttpClient client, Uri? userInfoEndpoint, string accessToken)
    {
        if (userInfoEndpoint is not null)
        {
            var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
            userInfoRequest.Headers.Add("Authorization", $"Bearer {accessToken}");
            var userInfoResponse = await client.SendAsync(userInfoRequest);

            if (userInfoResponse.IsSuccessStatusCode)
            {
                var userClaims = await userInfoResponse.Content.ReadFromJsonAsync<Dictionary<string, object?>>();
                return userClaims is not null
                    ? userClaims.Select(x => new Claim(x.Key, x.Value?.ToString() ?? string.Empty)).ToList()
                    : [];
            }
        }

        // Add default placeholder claim to make aspnet happy.
        return [new Claim("error", "unable_to_retrieve_user_info")];
    }
}

sealed internal class StateProperties : Dictionary<string, string>;
