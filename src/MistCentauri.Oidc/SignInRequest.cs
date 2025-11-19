namespace MistCentauri.Oidc;

internal record SignInRequest(string Authority, string ClientId, string ClientSecret, string Scope); 
