using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using MistCentauri.Oidc;
using MistCentauri.SimpleOidc;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddOidc(o =>
    {
        o.ChallengeTimeout = TimeSpan.FromMinutes(2);
        o.SignInRedirect = "/";
        o.SignOutRedirect = "/";
        o.ErrorRedirect = "/Login"; // TODO: Keep existing query params?
    })
    .AddAuthorization()
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o => o.LoginPath = new PathString("/Login"));

builder.Services.AddRazorPages();

var app = builder.Build();

app.UseHsts();
app.UseHttpsRedirection();
app.UseStatusCodePages();
app.UseMiddleware<ExceptionMiddleware>(); // For debugging
app.UseAntiforgery();
app.UseAuthentication();
app.UseAuthorization();

// For debugging
app.MapGet("/ticket", async context =>
{
    var ticket = await context.AuthenticateAsync();
    if (!ticket.Succeeded)
    {
        await context.Response.WriteAsync($"Signed Out");
        return;
    }

    foreach (var (key, value) in ticket.Properties.Items)
    {
        await context.Response.WriteAsync($"{key}: {value}\r\n");
    }
}).RequireAuthorization();

app.MapOidcEndpoints();
app.MapStaticAssets();
app.MapRazorPages();

app.Run();
