namespace MistCentauri.Oidc;

public sealed record SignInRequest(string Authority, string ClientId, string ClientSecret, string Scope); 
