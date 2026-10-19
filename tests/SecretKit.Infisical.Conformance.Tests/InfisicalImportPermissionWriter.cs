using System.Security.Cryptography;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class ImportPermissionWriter : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private long sequence;
    internal ImportPermissionPin Pin { get; }
    internal ImportPermissionWriter(ImportPermissionJournal journal, string writer) =>
        Pin = new(journal, writer, writer + "-channel", "import-permission-v1",
            Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    internal ImportPermissionSigned<T> Sign<T>(ImportPermissionRoot root, string window, T value)
    {
        var header = new ImportPermissionHeader(ImportPermissionContract.Hash(root), Pin.Journal, Pin.Writer,
            Pin.Channel, Pin.Schema, ImportPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()),
            Guid.NewGuid().ToString("N"), ++sequence, window);
        var payload = new ImportPermissionPayload<T>(header, value);
        byte[] bytes = ImportPermissionContract.Bytes(payload);
        try
        {
            return new(payload, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public void Dispose() => key.Dispose();
}
