using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace MistCentauri.SimpleOidc;

public static class Auth
{
    private const string RootPath = "/";
    private const string DeniedPath = "/denied";
    private const string SignInPath = "/signin";
    private const string SignOutPath = "/signout";

    public static IServiceCollection AddOidc(this IServiceCollection builder, OpenIdConnectOptions options)
    {
        return builder
            .AddAuthentication(o =>
            {
                o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(o =>
            {
                o.LoginPath = SignInPath;
                o.LogoutPath = SignOutPath;
            })
            .AddOpenIdConnect(o =>
            {
                o.Authority = options.Authority;
                o.ClientId = options.ClientId;
                o.ClientSecret = options.ClientSecret;

                o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                o.ResponseType = OpenIdConnectResponseType.Code;

                o.AccessDeniedPath = DeniedPath;
                
                o.SaveTokens = true;
                o.GetClaimsFromUserInfoEndpoint = true;
                o.MapInboundClaims = false;
                o.TokenValidationParameters.NameClaimType = "name";
                o.TokenValidationParameters.RoleClaimType = "role";
            }).Services;
    }
    
    public static IEndpointRouteBuilder MapAuthenticationRoutes(this IEndpointRouteBuilder builder)
    {
        builder.MapGet(DeniedPath, () => Results.Redirect(RootPath + "?denied=true"));
        builder.MapGet(SignOutPath, () => Results.Redirect(RootPath));

        builder.MapPost(SignInPath, async (HttpContext context, IAntiforgery antiforgery) =>
        {
            if (!await antiforgery.IsRequestValidAsync(context))
            {
                return Results.Redirect(RootPath);
            }

            return Results.Challenge(
                new() { RedirectUri = RootPath },
                [OpenIdConnectDefaults.AuthenticationScheme]);
        });

        builder.MapPost(SignOutPath, async (HttpContext context, IAntiforgery antiforgery) =>
        {
            if (!await antiforgery.IsRequestValidAsync(context))
            {
                return Results.Redirect(RootPath);
            }

            return Results.SignOut(
                new() { RedirectUri = RootPath },
                [CookieAuthenticationDefaults.AuthenticationScheme]);
        });


        return builder;
    }
}