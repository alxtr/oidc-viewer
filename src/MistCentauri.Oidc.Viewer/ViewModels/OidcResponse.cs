namespace MistCentauri.Oidc.Viewer.ViewModels;

public class OidcResponseModel
{
    public string? Email { get; set; }
    
    public OidcRequestModel Request { get; set; }
    
    public OidcTokenResponseModel Response { get; set; }
    
    public string? DecodedJwt { get; set; }
    
    public List<ClaimModel> Claims { get; set; }
}

public class OidcRequestModel
{
    public string? Authority { get; set; }
    
    public string? ClientId { get; set; }
    
    public List<string> Scopes { get; set; }
}

public class OidcTokenResponseModel
{
    public string? AccessToken { get; set; }
    
    public string? RefreshToken { get; set; }
    
    public string? TokenType { get; set; }
    
    public List<string> Scopes { get; set; }
    
    public string? ExpiresIn { get; set; }
    
    public string? ExpiresAt { get; set; }
}

public record ClaimModel(string Type, string Value);
