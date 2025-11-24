using System.Text.Json.Serialization;

namespace MistCentauri.Oidc;

sealed internal class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = null!;

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = null!;

    [JsonPropertyName("expires_in")]
    public string ExpiresIn { get; set; } = null!;
    
    [JsonPropertyName("scope")]
    public string Scope { get; set; } = null!;

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = null!;
}
