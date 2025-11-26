using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MistCentauri.SimpleOidc.ViewModels;

namespace MistCentauri.SimpleOidc.Pages;

[Authorize]
public class IndexModel : PageModel
{
    public OidcResponseModel OidcResponse { get; private set; } = new();

    public async Task<IActionResult> OnGetAsync()
    {
        var ticket = await HttpContext.AuthenticateAsync();
        if (!ticket.Succeeded)
        {
            return Challenge();
        }

        string? accessToken = await HttpContext.GetTokenAsync("access_token");
        string? refreshToken = await HttpContext.GetTokenAsync("refresh_token");
        string? tokenType = await HttpContext.GetTokenAsync("token_type");
        string? scope = await HttpContext.GetTokenAsync("scope");
        string? expiresIn = await HttpContext.GetTokenAsync("expires_in");
        string? expiresAt = await HttpContext.GetTokenAsync("expires_at");

        OidcResponse.Request = new OidcRequestModel()
        {
            Authority = ticket.Properties.Items["authority"],
            ClientId = ticket.Properties.Items["client_id"],
            Scopes = ticket.Properties.Items["scope"]?.Split(' ').ToList() ?? [],
        };

        OidcResponse.Response = new OidcTokenResponseModel()
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            TokenType = tokenType,
            Scopes = scope?.Split(' ').ToList() ?? [],
            ExpiresIn = expiresIn,
            ExpiresAt = !string.IsNullOrWhiteSpace(expiresAt) ? DateTime.Parse(expiresAt).ToString("yyyy-MM-dd HH:mm:ss") : string.Empty
        };

        JwtSecurityToken? jwt = null;
        try
        {
            jwt = new JwtSecurityToken(jwtEncodedString: accessToken);
        }
        catch
        {
            // ignored
        }

        OidcResponse.DecodedJwt = DecodeJwt(jwt);

        OidcResponse.Claims = HttpContext.User.Claims
            .Select(x => new ClaimModel(x.Type, x.Value))
            .ToList();

        OidcResponse.Email = FindEmail(HttpContext.User, jwt);

        return Page();
    }

    private string? DecodeJwt(JwtSecurityToken? jwt)
    {
        if (jwt is null)
            return null;

        try
        {
            JsonDocument parsedPayload = JsonDocument.Parse(jwt.Payload.SerializeToJson());
            return JsonSerializer.Serialize(parsedPayload.RootElement, new JsonSerializerOptions
            {
                WriteIndented = true
            });
        }
        catch
        {
            return null;
        }
    }

    private string FindEmail(ClaimsPrincipal principal, JwtSecurityToken? accessToken)
    {
        // Try claims first
        if (principal.FindFirst("email") is { Value: var value })
        {
            return value;
        }

        // Fallback to access token
        if (accessToken?.Payload[JwtRegisteredClaimNames.Email] is string email)
        {
            return email;
        }

        return "<unknown>";
    }
}
