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

    public static IServiceCollection AddOidcAuthentication(this IServiceCollection builder, IConfiguration configuration)
    {
        OidcSettings? oidcSettings = configuration.GetSection(nameof(OidcSettings)).Get<OidcSettings>();

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
                o.Authority = oidcSettings?.Authority;
                o.ClientId = oidcSettings?.ClientId;
                o.ClientSecret = oidcSettings?.ClientSecret;

                o.Scope.Clear();
                foreach (var scope in oidcSettings?.Scopes.Split(' ') ?? [])
                {
                    o.Scope.Add(scope);
                }

                o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                o.AccessDeniedPath = DeniedPath;

                o.UsePkce = true;
                o.ResponseType = OpenIdConnectResponseType.Code;
                o.SaveTokens = true;

                o.Events = new OpenIdConnectEvents()
                {
                    OnAuthenticationFailed = c =>
                    {
                        c.HandleResponse();

                        c.Response.StatusCode = 500;
                        c.Response.ContentType = "text/plain";
                        return c.Response.WriteAsync(c.Exception.ToString());
                    }
                };
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
            
            // Get .well-known
            
            // Create redirect uri from form post
            
            // 
            
            
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
