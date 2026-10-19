using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Coordinator has its own transport credential and an unrelated signing key.
// It can transport genuine journal records, but cannot authenticate any journal.
internal sealed class InfisicalImportPermissionFixtureSource(InfisicalImportPermissionFixture provider) : HttpMessageHandler
{
    private readonly ECDsa coordinator = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    internal InfisicalImportPermissionSource CreateClient() =>
        new(new(provider.Input(ImportPermissionAction.Read).Observer, this, length =>
        {
            var bytes = new byte[length]; provider.Copies.Add(bytes); return bytes;
        }), "import-coordinator", ImportPermissionSourceKind.ControlledFixture);
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (request.Headers.Authorization?.Parameter != "coordinator-token") return new(HttpStatusCode.Forbidden);
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token); provider.Copies.Add(bytes);
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var body = document.RootElement; NativeRunProtocol.RejectDuplicates(body);
            var root = body.GetProperty("root").Deserialize<ImportPermissionRoot>(ImportPermissionContract.Options)!;
            object facts;
            if (request.RequestUri!.AbsolutePath == "/import-permission/step")
            {
                var step = (ImportPermissionStep)body.GetProperty("step").GetInt32();
                if (step == ImportPermissionStep.Close) await provider.SealAndDrainAsync();
                var packet = provider.Step(root, step, body.TryGetProperty("capability", out var cap) ? cap.GetString() : null);
                if (provider.Fault == "forged-journal" && step == ImportPermissionStep.ObserveBefore)
                {
                    var genuine = packet.Requests[0];
                    byte[] content = ImportPermissionContract.Bytes(genuine.Payload);
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
                if (provider.Fault == "strip-action" && step == ImportPermissionStep.ObserveBefore)
                    packet = packet with { Decisions = packet.Decisions.Skip(1).ToArray() };
                if (provider.Fault == "tamper-commit" && step == ImportPermissionStep.Settle && packet.Commits.Length != 0)
                    packet.Commits[0] = packet.Commits[0] with
                    {
                        Payload = packet.Commits[0].Payload with
                        { Content = packet.Commits[0].Payload.Content with { PolicyHash = "tampered" } }
                    };
                if (provider.Fault == "forged-owner" && step == ImportPermissionStep.Open)
                {
                    byte[] content = ImportPermissionContract.Bytes(packet.Owner.Payload);
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
                observerIdentity = "import-coordinator",
                observedAt = DateTimeOffset.UtcNow,
                facts
            }, ImportPermissionContract.Options);
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
