using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalGroupPermissionFixtureSource(InfisicalGroupPermissionFixture provider) : HttpMessageHandler
{
    private readonly ECDsa coordinator = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    internal InfisicalGroupPermissionSource CreateClient() => new(
        new(provider.Input(GroupPermissionContract.Operations[0], GroupPermissionAction.Read).Observer, this,
            length => { var bytes = new byte[length]; provider.Copies.Add(bytes); return bytes; }),
        "group-coordinator", MemberPermissionSourceKind.ControlledFixture);
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (request.Headers.Authorization?.Parameter != "coordinator-token") return new(HttpStatusCode.Forbidden);
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token); provider.Copies.Add(bytes);
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var body = document.RootElement; NativeRunProtocol.RejectDuplicates(body);
            if (request.RequestUri!.AbsolutePath != "/group-permission/step") return new(HttpStatusCode.NotFound);
            var root = body.GetProperty("root").Deserialize<GroupPermissionRoot>(GroupPermissionContract.Options)!;
            var step = (GroupPermissionStep)body.GetProperty("step").GetInt32();
            if (step == GroupPermissionStep.Close) await provider.SealAndDrainAsync();
            var packet = provider.Step(root, step, body.TryGetProperty("capability", out var cap) ? cap.GetString() : null);
            if (provider.Fault == "interrupted-open" && step == GroupPermissionStep.Open)
            {
                provider.OpenEntered.TrySetResult();
                await provider.OpenRelease.Task.WaitAsync(token);
            }
            if (step == GroupPermissionStep.Open)
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
                    _ => packet
                };
                if (provider.Fault == "forged-seal") packet.Seals[0] = Forge(packet.Seals[0]);
            }
            if (provider.Fault == "missing-journal" && step == GroupPermissionStep.ObserveBefore)
                packet = packet with { Access = packet.Access with { Payload = packet.Access.Payload with { Content = [] } } };
            byte[] response = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                nonce = body.GetProperty("nonce").GetString(),
                observerIdentity = "group-coordinator",
                observedAt = DateTimeOffset.UtcNow,
                facts = packet
            }, GroupPermissionContract.Options);
            provider.Copies.Add(response);
            return new(HttpStatusCode.OK) { Content = new ClearingContent(response) };
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private GroupPermissionSigned<T> Forge<T>(GroupPermissionSigned<T> original)
    {
        byte[] bytes = GroupPermissionContract.Bytes(original.Payload);
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
internal sealed class InfisicalGroupPermissionWriter : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private long sequence;
    internal GroupPermissionPin Pin { get; }
    internal InfisicalGroupPermissionWriter(GroupPermissionJournal journal) =>
        Pin = new(journal, journal + "-writer", journal + "-channel", "group-v1", Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    internal GroupPermissionSigned<T> Sign<T>(GroupPermissionRoot root, GroupPermissionStep step, T value)
    {
        var payload = new GroupPermissionPayload<T>(new(GroupPermissionContract.Hash(root), Pin.Journal, Pin.Writer, Pin.Channel,
            Pin.Schema, GroupPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()), ++sequence, Guid.NewGuid().ToString("N"), step), value);
        byte[] bytes = GroupPermissionContract.Bytes(payload);
        try
        {
            return new(payload, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public void Dispose() => key.Dispose();
}
