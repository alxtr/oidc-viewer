using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MistCentauri.SimpleOidc.ViewModels;

namespace MistCentauri.SimpleOidc.Pages;

public class LoginModel : PageModel
{
    private readonly IConfiguration _configuration;
    
    public List<OidcPreset> Presets { get; private set; }

    public LoginModel(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    public IActionResult OnGet()
    {
        Presets = _configuration.GetSection("OidcPresets").Get<List<OidcPreset>>() ?? [];
        return Page();
    }
}
