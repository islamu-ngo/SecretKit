using System.Security.Cryptography;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class TagPermissionWriter : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private long sequence;
    internal TagPermissionPin Pin { get; }
    internal TagPermissionWriter(TagPermissionJournal journal, string writer) =>
        Pin = new(journal, writer, writer + "-channel", "tag-permission-v1",
            Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    internal TagPermissionSigned<T> Sign<T>(TagPermissionRoot root, string window, T value)
    {
        var header = new TagPermissionHeader(TagPermissionContract.Hash(root), Pin.Journal, Pin.Writer,
            Pin.Channel, Pin.Schema, TagPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()),
            Guid.NewGuid().ToString("N"), ++sequence, window);
        var payload = new TagPermissionPayload<T>(header, value);
        byte[] bytes = TagPermissionContract.Bytes(payload);
        try
        {
            return new(payload, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public void Dispose() => key.Dispose();
}
