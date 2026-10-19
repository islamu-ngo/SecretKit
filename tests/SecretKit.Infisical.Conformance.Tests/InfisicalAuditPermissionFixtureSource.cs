using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalAuditPermissionFixtureSource(InfisicalAuditPermissionFixture provider) : HttpMessageHandler
{
    private readonly ECDsa coordinator = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    internal InfisicalAuditPermissionSource CreateClient() => new(
        new(provider.Input(AuditPermissionContract.Operations[0], AuditPermissionAction.Read).Observer, this,
            length => { var bytes = new byte[length]; provider.Copies.Add(bytes); return bytes; }),
        "audit-coordinator", MemberPermissionSourceKind.ControlledFixture);
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (request.Headers.Authorization?.Parameter != "coordinator-token") return new(HttpStatusCode.Forbidden);
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token); provider.Copies.Add(bytes);
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var body = document.RootElement; NativeRunProtocol.RejectDuplicates(body);
            if (request.RequestUri!.AbsolutePath != "/audit-permission/step") return new(HttpStatusCode.NotFound);
            var root = body.GetProperty("root").Deserialize<AuditPermissionRoot>(AuditPermissionContract.Options)!;
            var step = (AuditPermissionStep)body.GetProperty("step").GetInt32();
            if (step == AuditPermissionStep.Close) await provider.SealAndDrainAsync();
            if (step is AuditPermissionStep.PublishedBefore or AuditPermissionStep.PublishedAfter) await provider.FencePublicationAsync();
            var packet = provider.Step(root, step, body.TryGetProperty("capability", out var cap) ? cap.GetString() : null);
            if (provider.Fault == "interrupted-open" && step == AuditPermissionStep.Open)
            {
                provider.OpenEntered.TrySetResult();
                await provider.OpenRelease.Task.WaitAsync(token);
            }
            if (step == AuditPermissionStep.Open)
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
                    "forged-publisher" => packet with { Publisher = Forge(packet.Publisher) },
                    _ => packet
                };
                if (provider.Fault == "forged-seal") packet.Seals[0] = Forge(packet.Seals[0]);
            }
            if (provider.Fault == "missing-journal" && step == AuditPermissionStep.ObserveBefore)
                packet = packet with { Access = packet.Access with { Payload = packet.Access.Payload with { Content = [] } } };
            byte[] response = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                nonce = body.GetProperty("nonce").GetString(),
                observerIdentity = "audit-coordinator",
                observedAt = DateTimeOffset.UtcNow,
                facts = packet
            }, AuditPermissionContract.Options);
            provider.Copies.Add(response);
            return new(HttpStatusCode.OK) { Content = new ClearingContent(response) };
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private AuditPermissionSigned<T> Forge<T>(AuditPermissionSigned<T> original)
    {
        byte[] bytes = AuditPermissionContract.Bytes(original.Payload);
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
internal sealed class InfisicalAuditPermissionWriter : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private long sequence;
    internal AuditPermissionPin Pin { get; }
    internal InfisicalAuditPermissionWriter(AuditPermissionJournal journal) =>
        Pin = new(journal, journal + "-writer", journal + "-channel", "audit-v1", Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    internal AuditPermissionSigned<T> Sign<T>(AuditPermissionRoot root, AuditPermissionStep step, T value)
    {
        var payload = new AuditPermissionPayload<T>(new(AuditPermissionContract.Hash(root), Pin.Journal, Pin.Writer, Pin.Channel,
            Pin.Schema, AuditPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()), ++sequence, Guid.NewGuid().ToString("N"), step), value);
        byte[] bytes = AuditPermissionContract.Bytes(payload);
        try
        {
            return new(payload, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public void Dispose() => key.Dispose();
}
