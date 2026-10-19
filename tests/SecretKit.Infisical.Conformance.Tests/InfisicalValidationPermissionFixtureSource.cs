using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalValidationPermissionFixtureSource(InfisicalValidationPermissionFixture provider) : HttpMessageHandler
{
    private readonly ECDsa coordinator = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    internal InfisicalValidationPermissionSource CreateClient() => new(
        new(provider.Input(ValidationPermissionContract.Operations[0], ValidationPermissionAction.Read).Observer, this,
            length => { var bytes = new byte[length]; provider.Copies.Add(bytes); return bytes; }),
        "validation-coordinator", MemberPermissionSourceKind.ControlledFixture);
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (request.Headers.Authorization?.Parameter != "coordinator-token") return new(HttpStatusCode.Forbidden);
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token); provider.Copies.Add(bytes);
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var body = document.RootElement; NativeRunProtocol.RejectDuplicates(body);
            if (request.RequestUri!.AbsolutePath != "/validation-permission/step") return new(HttpStatusCode.NotFound);
            var root = body.GetProperty("root").Deserialize<ValidationPermissionRoot>(ValidationPermissionContract.Options)!;
            var step = (ValidationPermissionStep)body.GetProperty("step").GetInt32();
            if (step == ValidationPermissionStep.Close) await provider.SealAndDrainAsync();
            var packet = provider.Step(root, step, body.TryGetProperty("capability", out var cap) ? cap.GetString() : null);
            if (provider.Fault == "interrupted-open" && step == ValidationPermissionStep.Open)
            {
                provider.OpenEntered.TrySetResult();
                await provider.OpenRelease.Task.WaitAsync(token);
            }
            if (step == ValidationPermissionStep.Open)
            {
                packet = provider.Fault switch
                {
                    "forged-journal" => packet with { Issuer = Forge(packet.Issuer) },
                    "forged-owner" => packet with { Owner = Forge(packet.Owner) },
                    "forged-ingress" => packet with { Ingress = Forge(packet.Ingress) },
                    "forged-policy" => packet with { Policy = Forge(packet.Policy) },
                    "forged-storage" => packet with { Storage = Forge(packet.Storage) },
                    "forged-membership" => packet with { Membership = Forge(packet.Membership) },
                    "forged-access" => packet with { Access = Forge(packet.Access) },
                    "forged-enforcement" => packet with { Enforcement = Forge(packet.Enforcement) },
                    "forged-backend" => packet with { Backend = Forge(packet.Backend) },
                    _ => packet
                };
                if (provider.Fault == "forged-seal") packet.Seals[0] = Forge(packet.Seals[0]);
            }
            if (provider.Fault == "missing-journal" && step == ValidationPermissionStep.ObserveBefore)
                packet = packet with { Access = packet.Access with { Payload = packet.Access.Payload with { Content = new ValidationPermissionAccesses([], [], [], []) } } };
            byte[] journal = JsonSerializer.SerializeToUtf8Bytes(packet, ValidationPermissionContract.Options);
            provider.Copies.Add(journal);
            using var packed = new MemoryStream();
            byte[] response;
            try
            {
                using (var encoder = new BrotliStream(packed, CompressionLevel.Fastest, leaveOpen: true)) encoder.Write(journal);
                response = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 1,
                    nonce = body.GetProperty("nonce").GetString(),
                    observerIdentity = "validation-coordinator",
                    observedAt = DateTimeOffset.UtcNow,
                    facts = new { encoding = "brotli-base64-v1", content = Convert.ToBase64String(packed.GetBuffer(), 0, checked((int)packed.Length)) }
                }, ValidationPermissionContract.Options);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(journal); CryptographicOperations.ZeroMemory(packed.GetBuffer());
            }
            provider.Copies.Add(response);
            return new(HttpStatusCode.OK) { Content = new ClearingContent(response) };
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private ValidationPermissionSigned<T> Forge<T>(ValidationPermissionSigned<T> original)
    {
        byte[] bytes = ValidationPermissionContract.Bytes(original.Payload);
        try
        {
            return original with
            {
                Signature = Convert.ToBase64String(coordinator.SignData(bytes,
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            };
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    protected override void Dispose(bool disposing)
    { if (disposing) coordinator.Dispose(); base.Dispose(disposing); }
    private sealed class ClearingContent : ByteArrayContent
    {
        private readonly byte[] bytes;
        internal ClearingContent(byte[] bytes) : base(bytes) => this.bytes = bytes;
        protected override void Dispose(bool disposing)
        { base.Dispose(disposing); if (disposing) CryptographicOperations.ZeroMemory(bytes); }
    }
}
internal sealed class InfisicalValidationPermissionWriter : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private long sequence;
    internal ValidationPermissionPin Pin { get; }
    internal InfisicalValidationPermissionWriter(ValidationPermissionJournal journal) =>
        Pin = new(journal, journal + "-writer", journal + "-channel", "validation-v1", Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    internal ValidationPermissionSigned<T> Sign<T>(ValidationPermissionRoot root, ValidationPermissionStep step, T value)
    {
        var payload = new ValidationPermissionPayload<T>(new(ValidationPermissionContract.Hash(root), Pin.Journal, Pin.Writer, Pin.Channel,
            Pin.Schema, ValidationPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()), ++sequence, Guid.NewGuid().ToString("N"), step), value);
        byte[] bytes = ValidationPermissionContract.Bytes(payload);
        try
        {
            return new(payload, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public void Dispose() => key.Dispose();
}
