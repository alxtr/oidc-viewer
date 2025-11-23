using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;

namespace MistCentauri.Oidc;

public interface IRandomGenerator
{
    string Generate();
}

sealed internal class UriSafeBase64RandomGenerator : IRandomGenerator
{
    public string Generate()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return WebEncoders.Base64UrlEncode(bytes);
    }
}
