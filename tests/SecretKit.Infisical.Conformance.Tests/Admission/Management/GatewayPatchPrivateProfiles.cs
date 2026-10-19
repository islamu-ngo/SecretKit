using System.Security.Cryptography;
using System.Text.Json;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class GatewayPatchPrivateProfiles : IDisposable
{
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private byte[] baseline = [];
    private byte[] selected = [];
    private bool disposed;

    internal GatewayPatchPrivateProfiles(GatewayPatchAuthenticationInput original,
        GatewayPatchAuthenticationInput changed, Func<GatewayPatchAuthenticationInput, byte[]>? encode = null)
    {
        try
        {
            // Identity has a response-only branch; a native source owns that
            // baseline. It must never be fabricated as a public creation input.
            using var first = original.Method == SecretKit.Infisical.Management.GatewayAuthenticationMethod.Identity ?
                null : original.Create();
            using var second = changed.Method == SecretKit.Infisical.Management.GatewayAuthenticationMethod.Identity ?
                null : changed.Create();
            encode ??= value => JsonSerializer.SerializeToUtf8Bytes(value, Json);
            baseline = encode(original);
            selected = encode(changed);
        }
        catch { Dispose(); throw; }
    }

    internal void Write(Utf8JsonWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        byte[] first = baseline.ToArray();
        byte[] second = [];
        try
        {
            second = selected.ToArray();
            writer.WriteStartObject("profiles");
            writer.WritePropertyName("baseline");
            writer.WriteRawValue(first);
            writer.WritePropertyName("selected");
            writer.WriteRawValue(second);
            writer.WriteEndObject();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
        }
    }
    public void Dispose()
    {
        disposed = true;
        CryptographicOperations.ZeroMemory(baseline);
        CryptographicOperations.ZeroMemory(selected);
    }
    public override string ToString() => "[GatewayPatchPrivateProfiles]";
}
