using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using MistCentauri.Oidc;
using MistCentauri.Oidc.Viewer.ViewModels;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddProblemDetails()
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

builder.Services.AddRazorPages();
builder.Services.AddAntiforgery(o =>
{
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

builder.Services.Configure<OidcPresets>(builder.Configuration.GetSection(nameof(OidcPresets)));
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedProto |
                               ForwardedHeaders.XForwardedHost;

    var hosts = builder.Configuration["ForwardedHeaders:AllowedHosts"]?.Split([';'], StringSplitOptions.RemoveEmptyEntries);
    options.AllowedHosts = hosts ?? ["*.localhost"]; // This is not meant for public or production use.
    options.KnownProxies.Clear();
    options.KnownIPNetworks.Clear();
});

var app = builder.Build();

app.UseForwardedHeaders();
app.UseHsts();
app.UseHttpsRedirection();
app.UseExceptionHandler("/Error");
app.UseStatusCodePages();
app.UseAntiforgery();
app.UseAuthentication();
app.UseAuthorization();

app.MapOidcEndpoints();
app.MapStaticAssets();
app.MapRazorPages();

app.Run();
