using System.Text.Json.Serialization;

namespace MistCentauri.Oidc;

sealed internal class TokenErrorResponse
{
    [JsonPropertyName("error")]
    public string? Error { get; set; }
    
    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; set; }
}
