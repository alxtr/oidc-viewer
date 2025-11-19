using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;

namespace MistCentauri.Oidc;

public class StateProperties : Dictionary<string, string>;

public static class EndpointRouteBuilderExtensions
{
    private const string CodeVerifierProperty = "code_verifier";
    private const string CorrelationProperty = "correlation_id";
    private const string CodeChallengeKey = "code_challenge";
    private const string CodeChallengeMethodKey = "code_challenge_method";

    private const string RootPath = "/";
    private const string SignInPath = "/signin";
    private const string SignInCallbackPath = "/signin-callback";

    public static IEndpointRouteBuilder MapOidcEndpoints(this IEndpointRouteBuilder builder)
    {
        builder.MapPost(SignInPath, async (HttpContext context, IAntiforgery antiforgery, WellKnownDocumentCache documentCache, ChallengeCache challengeCache, IWebDataProtector<StateProperties> protector, [FromForm] SignInRequest signInRequest) =>
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
            
            var bytes = new byte[32];
            RandomNumberGenerator.Fill(bytes);
            var codeVerifier = Base64UrlTextEncoder.Encode(bytes);

            var challengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
            var codeChallenge = WebEncoders.Base64UrlEncode(challengeBytes);

            parameters[CodeChallengeKey] = codeChallenge;
            parameters[CodeChallengeMethodKey] = "S256";

            // TODO: Create correlation id

            StateProperties state = new StateProperties()
            {
                { CorrelationProperty, Guid.NewGuid().ToString() },
                { CodeVerifierProperty, codeVerifier}
            };

            parameters["state"] = protector.Protect(state);

            var challenge = new ChallengeData(signInRequest.Authority, signInRequest.ClientId, signInRequest.ClientSecret, codeVerifier);
            challengeCache.Store(state[CorrelationProperty], challenge);

            var challengeUri = BuildChallengeUrl(wellKnown.AuthorizationEnpoint, parameters);
            return Results.Redirect(challengeUri);
        });

        builder.MapGet(SignInCallbackPath, async (HttpContext context, IHttpClientFactory factory, WellKnownDocumentCache documentCache, ChallengeCache challengeCache, IWebDataProtector<StateProperties> protector, [FromQuery] string state, [FromQuery] string code) =>
        {
            StateProperties? stateProperties = protector.Unprotect(state);

            if (stateProperties is null)
            {
                return Results.BadRequest("Invalid state");
            }

            // TODO: Validate correlation id

            ChallengeData? challenge = challengeCache.Get(stateProperties[CorrelationProperty]);
            if (challenge is null)
            {
                return Results.BadRequest("Invalid state");
            }

            WellKnownDocument? wellKnown = await documentCache.GetAsync(challenge.Authority);
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
                new KeyValuePair<string, string>("client_id", challenge.ClientId),
                new KeyValuePair<string, string>("client_secret", challenge.ClientSecret),
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

    private static string BuildChallengeUrl(Uri authorizationEndpoint, Dictionary<string, string?> parameters)
        => QueryHelpers.AddQueryString(authorizationEndpoint.ToString(), parameters);
    
    private static string BuildRedirectUri(HttpRequest request, string targetPath)
        => request.Scheme + Uri.SchemeDelimiter + request.Host + targetPath;
}

public class UserToken
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }
}
