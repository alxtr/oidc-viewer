namespace MistCentauri.Oidc.Viewer.ViewModels;

public class OidcPresets
{
    public string? Default { get; set; }

    public List<OidcPreset>? Presets { get; set; } = [];
}

public class OidcPreset
{
    public string Name { get; set; }
    
    public OidcSettings Settings { get; set; }
}

public class OidcSettings
{
    public string Authority { get; set; }
    
    public string ClientId { get; set; }
    
    public string ClientSecret { get; set; }
    
    public string Scopes { get; set; }
}
