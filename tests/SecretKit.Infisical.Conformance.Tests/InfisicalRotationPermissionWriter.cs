using System.Security.Cryptography;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class RotationPermissionWriter : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private long sequence;
    internal RotationPermissionPin Pin { get; }
    internal RotationPermissionWriter(RotationPermissionJournal journal, string writer) =>
        Pin = new(journal, writer, writer + "-channel", "rotation-permission-v1",
            Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    internal RotationPermissionSigned<T> Sign<T>(RotationPermissionRoot root, string window, T value)
    {
        var payload = new RotationPermissionPayload<T>(new(RotationPermissionContract.Hash(root), Pin.Journal,
            Pin.Writer, Pin.Channel, Pin.Schema, Guid.NewGuid().ToString("N"), ++sequence, window), value);
        byte[] bytes = RotationPermissionContract.Bytes(payload);
        try
        {
            return new(payload, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public void Dispose() => key.Dispose();
}
