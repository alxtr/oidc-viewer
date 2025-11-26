using Microsoft.AspNetCore.Authentication.Cookies;
using MistCentauri.Oidc;
using MistCentauri.SimpleOidc;
using MistCentauri.SimpleOidc.ViewModels;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddOidc(o =>
    {
        o.ChallengeTimeout = TimeSpan.FromMinutes(2);
        o.SignInRedirect = "/";
        o.SignOutRedirect = "/";
        o.ErrorRedirect = "/Login?ReturnUrl=%2F"; // Good enough for now
    })
    .AddAuthorization()
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o => o.LoginPath = new PathString("/Login"));

builder.Services.Configure<OidcPresets>(builder.Configuration.GetSection(nameof(OidcPresets)));

builder.Services.AddRazorPages();

var app = builder.Build();

app.UseHsts();
app.UseHttpsRedirection();
app.UseStatusCodePages();
app.UseMiddleware<ExceptionMiddleware>(); // For debugging
app.UseAntiforgery();
app.UseAuthentication();
app.UseAuthorization();

app.MapOidcEndpoints();
app.MapStaticAssets();
app.MapRazorPages();

app.Run();
