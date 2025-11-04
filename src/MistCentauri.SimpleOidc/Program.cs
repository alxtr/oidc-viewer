using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using MistCentauri.SimpleOidc;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddOidc(builder.Configuration.GetSection(OpenIdConnectDefaults.AuthenticationScheme).Get<OpenIdConnectOptions>()!)
    .AddAuthorization();

var app = builder.Build();

app.UseDeveloperExceptionPage();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapAuthenticationRoutes();

app.MapGet("/", async context =>
{
    if (context.User.Identity?.IsAuthenticated ?? false)
    {
        var response = context.Response;
        response.ContentType = "text/html";
        await response.WriteAsync("<html><body>");
        await response.WriteAsync("Hello " + (context.User.Identity.Name ?? "anonymous") + "<br>");
        foreach (var claim in context.User.Claims)
        {
            await response.WriteAsync(claim.Type + ": " + claim.Value + "<br>");
        }

        await response.WriteAsync("Tokens:<br>");

        await response.WriteAsync("Access Token: " + await context.GetTokenAsync("access_token") + "<br>");
        await response.WriteAsync("Refresh Token: " + await context.GetTokenAsync("refresh_token") + "<br>");
        await response.WriteAsync("Token Type: " + await context.GetTokenAsync("token_type") + "<br>");
        await response.WriteAsync("expires_at: " + await context.GetTokenAsync("expires_at") + "<br>");
        await response.WriteAsync("<a href=\"/signout\">Sign out</a><br>");
        await response.WriteAsync("</body></html>");
    }
    else
    {
        var response = context.Response;
        response.ContentType = "text/html";
        await response.WriteAsync("<html><body>");
        await response.WriteAsync("<a href=\"/signin\">Sign in</a><br>");
        await response.WriteAsync("</body></html>");
    }
});

app.Run();
