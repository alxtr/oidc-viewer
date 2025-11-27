using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Options;
using MistCentauri.Oidc;
using MistCentauri.Oidc.Viewer.ViewModels;

namespace MistCentauri.Oidc.Viewer.Pages;

public class LoginModel : PageModel
{
    private readonly OidcPresets _presets;
    private readonly IWebDataProtector<string> _clientSecretProtector;
    
    public List<SelectListItem> Presets { get; set; }

    public LoginModel(IOptions<OidcPresets> presets, IWebDataProtector<string> clientSecretProtector)
    {
        _presets = presets.Value;
        _clientSecretProtector = clientSecretProtector;
    }

    public IActionResult OnGet()
    {
        Presets = _presets.Presets?
            .Select(x => new SelectListItem(
                x.Name, 
                GetPresetValue(x), 
                x.Name.Equals(_presets.Default, StringComparison.InvariantCulture)))
            .ToList() ?? [];

        return Page();
    }

    private string GetPresetValue(OidcPreset preset)
    {
        string authority = Base64Encode(preset.Settings.Authority);
        string clientId = Base64Encode(preset.Settings.ClientId);
        string clientSecret = Base64Encode(_clientSecretProtector.Protect(preset.Settings.ClientSecret));
        string scopes = Base64Encode(preset.Settings.Scopes);

        return $"{authority}:{clientId}:{clientSecret}:{scopes}";
    }

    private static string Base64Encode(string data) 
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(data);
        return Convert.ToBase64String(bytes);
    }
}
