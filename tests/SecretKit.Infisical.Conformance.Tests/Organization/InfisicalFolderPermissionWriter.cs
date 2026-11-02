using System.Security.Cryptography;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class FolderPermissionWriter : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private long sequence;
    internal FolderPermissionPin Pin { get; }
    internal FolderPermissionWriter(FolderPermissionJournal journal, string writer) =>
        Pin = new(journal, writer, writer + "-channel", "folder-permission-v1",
            Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    internal FolderPermissionSigned<T> Sign<T>(FolderPermissionRoot root, string window, T value)
    {
        var header = new FolderPermissionHeader(FolderPermissionContract.Hash(root), Pin.Journal, Pin.Writer,
            Pin.Channel, Pin.Schema, FolderPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()),
            Guid.NewGuid().ToString("N"), ++sequence, window);
        var payload = new FolderPermissionPayload<T>(header, value);
        byte[] bytes = FolderPermissionContract.Bytes(payload);
        try
        {
            return new(payload, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public void Dispose() => key.Dispose();
}
