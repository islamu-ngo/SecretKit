using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Coordinator has its own transport credential and an unrelated signing key.
// It can transport genuine journal records, but cannot authenticate any journal.
internal sealed class InfisicalFolderPermissionFixtureSource(InfisicalFolderPermissionFixture provider) : HttpMessageHandler
{
    private readonly ECDsa coordinator = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    internal InfisicalFolderPermissionSource CreateClient() =>
        new(new(provider.Input(FolderPermissionAction.Read).Observer, this, length =>
        {
            var bytes = new byte[length]; provider.Copies.Add(bytes); return bytes;
        }), "folder-coordinator", FolderPermissionSourceKind.ControlledFixture);
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (request.Headers.Authorization?.Parameter != "coordinator-token") return new(HttpStatusCode.Forbidden);
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token); provider.Copies.Add(bytes);
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var body = document.RootElement; NativeRunProtocol.RejectDuplicates(body);
            var root = body.GetProperty("root").Deserialize<FolderPermissionRoot>(FolderPermissionContract.Options)!;
            object facts;
            if (request.RequestUri!.AbsolutePath == "/folder-permission/step")
            {
                var step = (FolderPermissionStep)body.GetProperty("step").GetInt32();
                if (step == FolderPermissionStep.Close) await provider.SealAndDrainAsync();
                var packet = provider.Step(root, step, body.TryGetProperty("capability", out var cap) ? cap.GetString() : null);
                if (provider.Fault == "forged-journal" && step == FolderPermissionStep.ObserveBefore)
                {
                    var genuine = packet.Requests[0];
                    byte[] content = FolderPermissionContract.Bytes(genuine.Payload);
                    try
                    {
                        packet.Requests[0] = genuine with
                        {
                            Signature = Convert.ToBase64String(coordinator.SignData(content,
                        HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                        };
                    }
                    finally { CryptographicOperations.ZeroMemory(content); }
                }
                if (provider.Fault == "strip-action" && step == FolderPermissionStep.ObserveBefore)
                    packet = packet with { Decisions = packet.Decisions.Skip(1).ToArray() };
                if (provider.Fault == "tamper-commit" && step == FolderPermissionStep.Settle && packet.Commits.Length != 0)
                    packet.Commits[0] = packet.Commits[0] with
                    {
                        Payload = packet.Commits[0].Payload with
                        { Content = packet.Commits[0].Payload.Content with { PolicyHash = "tampered" } }
                    };
                if (provider.Fault == "forged-owner" && step == FolderPermissionStep.Open)
                {
                    byte[] content = FolderPermissionContract.Bytes(packet.Owner.Payload);
                    try
                    {
                        packet = packet with
                        {
                            Owner = packet.Owner with
                            {
                                Signature = Convert.ToBase64String(coordinator.SignData(
                        content, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                            }
                        };
                    }
                    finally { CryptographicOperations.ZeroMemory(content); }
                }
                facts = packet;
            }
            else return new(HttpStatusCode.NotFound);
            byte[] response = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                nonce = body.GetProperty("nonce").GetString(),
                observerIdentity = "folder-coordinator",
                observedAt = DateTimeOffset.UtcNow,
                facts
            }, FolderPermissionContract.Options);
            provider.Copies.Add(response);
            return new(HttpStatusCode.OK) { Content = new ClearingContent(response) };
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
