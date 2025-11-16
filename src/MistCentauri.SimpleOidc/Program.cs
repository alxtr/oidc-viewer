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
app.UseRouting();
app.UseAntiforgery();

app.MapOidc();
app.MapStaticAssets();
app.MapRazorPages();

app.Run();
