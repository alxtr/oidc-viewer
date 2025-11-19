using MistCentauri.Oidc;
using MistCentauri.SimpleOidc;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddOidc()
    .AddRazorPages();

var app = builder.Build();

app.UseHsts();
app.UseHttpsRedirection();
app.UseStatusCodePages();
app.UseMiddleware<ExceptionMiddleware>(); // For debugging
app.UseAntiforgery();

app.MapOidcEndpoints();
app.MapStaticAssets();
app.MapRazorPages();

app.Run();
