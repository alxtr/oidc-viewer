using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(sharedOptions =>
    {
        sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        sharedOptions.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect(o =>
    {
        o.Authority = builder.Configuration["OpenIdConnect:Authority"];
        o.ClientId = builder.Configuration["OpenIdConnect:ClientId"];
        o.ClientSecret = builder.Configuration["OpenIdConnect:ClientSecret"];

        o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.ResponseType = OpenIdConnectResponseType.Code;

        o.SaveTokens = true;
        o.GetClaimsFromUserInfoEndpoint = true;
        o.MapInboundClaims = false;
        o.TokenValidationParameters.NameClaimType = "name";
        o.TokenValidationParameters.RoleClaimType = "role";
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseDeveloperExceptionPage();
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", async context =>
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
    await response.WriteAsync("<a href=\"/signout-oidc\">Logout</a><br>");
    await response.WriteAsync("</body></html>");
}).RequireAuthorization();

app.Run();
