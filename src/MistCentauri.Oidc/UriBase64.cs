using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace MistCentauri.Oidc;

internal static class UriBase64
{
    public static string Encode(string data) 
    {
        var bytes = Encoding.UTF8.GetBytes(data);
        return WebEncoders.Base64UrlEncode(bytes);
    }
    
    public static string Decode(string data)
    {
        var bytes = WebEncoders.Base64UrlDecode(data);
        return Encoding.UTF8.GetString(bytes);
    }
}
