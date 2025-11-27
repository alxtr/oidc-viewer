namespace MistCentauri.Oidc;

public sealed class OidcOptions
{
    public string SignInRedirect { get; set; } = "/";
    
    public string SignOutRedirect { get; set; } = "/";

    public string ErrorRedirect { get; set; } = "/error";
    
    public TimeSpan ChallengeTimeout { get; set; } = TimeSpan.FromMinutes(15);
}
