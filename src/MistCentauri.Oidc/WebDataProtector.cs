using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace MistCentauri.Oidc;

public interface IWebDataProtector<T>
{
    string Protect(T data);

    T? Unprotect(string protectedText);
}

sealed internal class WebDataProtector<T> : IWebDataProtector<T>
{
    private readonly IDataProtector _protector;

    public WebDataProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector(nameof(T));
    }

    public string Protect(T data)
    {
        var json = JsonSerializer.Serialize(data);
        var protectedData = _protector.Protect(json);
        return UriBase64.Encode(protectedData);
    }

    public T? Unprotect(string protectedText)
    {
        try
        {
            var protectedData = UriBase64.Decode(protectedText);
            var json = _protector.Unprotect(protectedData);
            return JsonSerializer.Deserialize<T>(json);
        }
        catch
        {
            return default;
        }
    }
}
