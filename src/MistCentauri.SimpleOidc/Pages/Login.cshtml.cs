using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Options;
using MistCentauri.Oidc;
using MistCentauri.SimpleOidc.ViewModels;

namespace MistCentauri.SimpleOidc.Pages;

public class LoginModel : PageModel
{
    public List<SelectListItem> Presets { get; set; }

    public LoginModel(IOptions<OidcPresets> presets, IWebDataProtector<string> clientSecretProtector)
    {
        Presets = presets.Value.Presets
            .Select(x => new SelectListItem(
                x.Name, 
                GetPresetValue(x, clientSecretProtector), 
                x.Name.Equals(presets.Value.Default, StringComparison.InvariantCulture)))
            .ToList();
    }

    public IActionResult OnGet()
        => Page();

    private string GetPresetValue(OidcPreset preset, IWebDataProtector<string> clientSecretProtector)
    {
        string authority = Base64Encode(preset.Settings.Authority);
        string clientId = Base64Encode(preset.Settings.ClientId);
        string clientSecret = Base64Encode(clientSecretProtector.Protect(preset.Settings.ClientSecret));
        string scopes = Base64Encode(preset.Settings.Scopes);

        return $"{authority}:{clientId}:{clientSecret}:{scopes}";
    }

    private static string Base64Encode(string data) 
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(data);
        return Convert.ToBase64String(bytes);
    }
}
