namespace MistCentauri.SimpleOidc;

public class OidcSettings
{
    public string Authority { get; set; } = string.Empty;
    
    public string ClientId { get; set; } = string.Empty;
    
    public string ClientSecret { get; set; } = string.Empty;

    public string Scopes { get; set; } = string.Empty;
}