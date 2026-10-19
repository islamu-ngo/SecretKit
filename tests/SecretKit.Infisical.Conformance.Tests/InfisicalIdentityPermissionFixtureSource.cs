using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalIdentityPermissionFixtureSource(InfisicalIdentityPermissionFixture provider) : HttpMessageHandler
{
    private readonly ECDsa coordinator = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    internal InfisicalIdentityPermissionSource CreateClient() => new(
        new(provider.Input(IdentityPermissionContract.Operations[0], IdentityPermissionAction.Read).Observer, this,
            length => { var bytes = new byte[length]; provider.Copies.Add(bytes); return bytes; }),
        "identity-coordinator", MemberPermissionSourceKind.ControlledFixture);
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (request.Headers.Authorization?.Parameter != "coordinator-token") return new(HttpStatusCode.Forbidden);
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token); provider.Copies.Add(bytes);
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var body = document.RootElement; NativeRunProtocol.RejectDuplicates(body);
            if (request.RequestUri!.AbsolutePath == "/identity-permission/capture")
            {
                var selected = body.GetProperty("root").Deserialize<IdentityPermissionRoot>(IdentityPermissionContract.Options)!;
                await provider.CaptureAsync(selected, body.GetProperty("row").GetString()!, body.GetProperty("tokenId").GetString()!, body.GetProperty("material").GetString()!, token);
                byte[] acknowledgement = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 1,
                    nonce = body.GetProperty("nonce").GetString(),
                    observerIdentity = "identity-coordinator",
                    observedAt = DateTimeOffset.UtcNow,
                    facts = new { captured = true }
                });
                provider.Copies.Add(acknowledgement); return new(HttpStatusCode.OK) { Content = new ClearingContent(acknowledgement) };
            }
            if (request.RequestUri.AbsolutePath != "/identity-permission/step") return new(HttpStatusCode.NotFound);
            var root = body.GetProperty("root").Deserialize<IdentityPermissionRoot>(IdentityPermissionContract.Options)!;
            var step = (IdentityPermissionStep)body.GetProperty("step").GetInt32();
            if (step == IdentityPermissionStep.Close) await provider.SealAndDrainAsync();
            var packet = provider.Step(root, step, body.TryGetProperty("capability", out var cap) ? cap.GetString() : null);
            if (provider.Fault == "interrupted-open" && step == IdentityPermissionStep.Open)
            {
                provider.OpenEntered.TrySetResult();
                await provider.OpenRelease.Task.WaitAsync(token);
            }
            if (step == IdentityPermissionStep.Open)
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
                    "forged-capture" => packet with { Capture = Forge(packet.Capture) },
                    "forged-token-state" => packet with { TokenState = Forge(packet.TokenState) },
                    _ => packet
                };
                if (provider.Fault == "forged-seal") packet.Seals[0] = Forge(packet.Seals[0]);
            }
            if (provider.Fault == "missing-journal" && step == IdentityPermissionStep.ObserveBefore)
                packet = packet with
                {
                    Access = packet.Access with
                    {
                        Payload = packet.Access.Payload with
                        { Content = packet.Access.Payload.Content with { Decisions = [] } }
                    }
                };
            byte[] response = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                nonce = body.GetProperty("nonce").GetString(),
                observerIdentity = "identity-coordinator",
                observedAt = DateTimeOffset.UtcNow,
                facts = packet
            }, IdentityPermissionContract.Options);
            provider.Copies.Add(response);
            return new(HttpStatusCode.OK) { Content = new ClearingContent(response) };
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private IdentityPermissionSigned<T> Forge<T>(IdentityPermissionSigned<T> original)
    {
        byte[] bytes = IdentityPermissionContract.Bytes(original.Payload);
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
internal sealed class InfisicalIdentityPermissionWriter : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private long sequence;
    internal IdentityPermissionPin Pin { get; }
    internal InfisicalIdentityPermissionWriter(IdentityPermissionJournal journal) =>
        Pin = new(journal, journal + "-writer", journal + "-channel", "identity-v1", Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    internal IdentityPermissionSigned<T> Sign<T>(IdentityPermissionRoot root, IdentityPermissionStep step, T value)
    {
        var payload = new IdentityPermissionPayload<T>(new(IdentityPermissionContract.Hash(root), Pin.Journal, Pin.Writer, Pin.Channel,
            Pin.Schema, IdentityPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()), ++sequence, Guid.NewGuid().ToString("N"), step), value);
        byte[] bytes = IdentityPermissionContract.Bytes(payload);
        try
        {
            return new(payload, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public void Dispose() => key.Dispose();
}
