// using System.Security.Cryptography;
// using Microsoft.Extensions.Options;
//
// namespace MistCentauri.Oidc;
//
// public class CorrelationId
// {
//     
//     protected virtual string GenerateCorrelationId()
//     {
//         ArgumentNullException.ThrowIfNull(properties);
//
//         var bytes = new byte[32];
//         RandomNumberGenerator.Fill(bytes);
//         var correlationId = Base64UrlTextEncoder.Encode(bytes);
//
//         var cookieOptions = Options.CorrelationCookie.Build(Context, TimeProvider.GetUtcNow());
//
//         properties.Items[CorrelationProperty] = correlationId;
//
//         var cookieName = Options.CorrelationCookie.Name + correlationId;
//
//         Response.Cookies.Append(cookieName, CorrelationMarker, cookieOptions);
//     }   
// }
