using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalProxyPermissionFixtureSource(InfisicalProxyPermissionFixture provider) : HttpMessageHandler
{
    private readonly ECDsa coordinator = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    internal InfisicalProxyPermissionSource CreateClient() => new(
        new(provider.Input(ProxyPermissionContract.Operations[0], ProxyPermissionAction.Read).Observer, this,
            length => { var bytes = new byte[length]; provider.Copies.Add(bytes); return bytes; }),
        "proxy-coordinator", MemberPermissionSourceKind.ControlledFixture);
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (request.Headers.Authorization?.Parameter != "coordinator-token") return new(HttpStatusCode.Forbidden);
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token); provider.Copies.Add(bytes);
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var body = document.RootElement; NativeRunProtocol.RejectDuplicates(body);
            if (request.RequestUri!.AbsolutePath != "/proxy-permission/step") return new(HttpStatusCode.NotFound);
            var root = body.GetProperty("root").Deserialize<ProxyPermissionRoot>(ProxyPermissionContract.Options)!;
            var step = (ProxyPermissionStep)body.GetProperty("step").GetInt32();
            if (step == ProxyPermissionStep.Close) await provider.SealAndDrainAsync();
            var packet = provider.Step(root, step, body.TryGetProperty("capability", out var cap) ? cap.GetString() : null);
            if (provider.Fault == "interrupted-open" && step == ProxyPermissionStep.Open)
            {
                provider.OpenEntered.TrySetResult();
                await provider.OpenRelease.Task.WaitAsync(token);
            }
            if (step == ProxyPermissionStep.Open)
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
                    "forged-collection" => packet with { Collection = Forge(packet.Collection) },
                    _ => packet
                };
                if (provider.Fault == "forged-seal") packet.Seals[0] = Forge(packet.Seals[0]);
            }
            if (provider.Fault == "missing-journal" && step == ProxyPermissionStep.ObserveBefore)
                packet = packet with { Access = packet.Access with { Payload = packet.Access.Payload with { Content = [] } } };
            byte[] response = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                nonce = body.GetProperty("nonce").GetString(),
                observerIdentity = "proxy-coordinator",
                observedAt = DateTimeOffset.UtcNow,
                facts = packet
            }, ProxyPermissionContract.Options);
            provider.Copies.Add(response);
            return new(HttpStatusCode.OK) { Content = new ClearingContent(response) };
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private ProxyPermissionSigned<T> Forge<T>(ProxyPermissionSigned<T> original)
    {
        byte[] bytes = ProxyPermissionContract.Bytes(original.Payload);
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
internal sealed class InfisicalProxyPermissionWriter : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private long sequence;
    internal ProxyPermissionPin Pin { get; }
    internal InfisicalProxyPermissionWriter(ProxyPermissionJournal journal) =>
        Pin = new(journal, journal + "-writer", journal + "-channel", "proxy-v1", Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    internal ProxyPermissionSigned<T> Sign<T>(ProxyPermissionRoot root, ProxyPermissionStep step, T value)
    {
        var payload = new ProxyPermissionPayload<T>(new(ProxyPermissionContract.Hash(root), Pin.Journal, Pin.Writer, Pin.Channel,
            Pin.Schema, ProxyPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()), ++sequence, Guid.NewGuid().ToString("N"), step), value);
        byte[] bytes = ProxyPermissionContract.Bytes(payload);
        try
        {
            return new(payload, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public void Dispose() => key.Dispose();
}
