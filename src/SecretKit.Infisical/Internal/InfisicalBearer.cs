using System.Buffers;
using System.Net.Http.Headers;
using SecretKit.Core;

namespace SecretKit.Infisical;

// Shared runtime/management bearer admission: rejected material is validated over a
// cleared snapshot and never revealed as a managed string.
internal static class InfisicalBearer
{
    internal const int MaximumLength = 16384;

    // RFC 6750 section 2.1 b64token: 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
    private static readonly SearchValues<char> TokenCharacters =
        SearchValues.Create("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-._~+/");

    internal static bool IsValid(ReadOnlySpan<char> token)
    {
        if (token.Length is < 1 or > MaximumLength) return false;
        ReadOnlySpan<char> body = token.TrimEnd('=');
        return !body.IsEmpty && !body.ContainsAnyExcept(TokenCharacters);
    }

    internal static AuthenticationHeaderValue? CreateHeader(SecretMaterial material) =>
        material.Use(static token => IsValid(token))
            ? new AuthenticationHeaderValue("Bearer", material.Reveal())
            : null;
}
