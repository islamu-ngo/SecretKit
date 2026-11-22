using System.Net.Http.Headers;
using SecretKit.Core;
using SecretKit.Internal;

namespace SecretKit.Infisical;

internal static class InfisicalBearer
{
    internal const int MaximumLength = BearerHeader.MaximumLength;
    internal static bool IsValid(ReadOnlySpan<char> token) => BearerHeader.IsValid(token);
    internal static AuthenticationHeaderValue? CreateHeader(SecretMaterial material) => BearerHeader.CreateHeader(material);
}
