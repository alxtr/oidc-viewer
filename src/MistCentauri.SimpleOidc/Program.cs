using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using MistCentauri.SimpleOidc;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddOidc(builder.Configuration.GetSection(OpenIdConnectDefaults.AuthenticationScheme).Get<OpenIdConnectOptions>()!)
    .AddAuthorization()
    .AddRazorPages();

var app = builder.Build();

app.UseHsts();
app.UseHttpsRedirection();
app.UseExceptionHandler("/error");
app.UseStatusCodePages();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapAuthenticationRoutes();
app.MapStaticAssets();
app.MapRazorPages()
    .WithStaticAssets();

app.Run();
