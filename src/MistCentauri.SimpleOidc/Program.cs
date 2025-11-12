using MistCentauri.SimpleOidc;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddOidc(builder.Configuration)
    .AddAuthorization()
    .AddRazorPages();

var app = builder.Build();

app.UseHsts();
app.UseHttpsRedirection();
app.UseStatusCodePages();
app.UseMiddleware<ExceptionMiddleware>();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapAuthenticationRoutes();
app.MapStaticAssets();
app.MapRazorPages()
    .WithStaticAssets();

app.Run();
