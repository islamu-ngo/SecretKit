using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// The coordinator can collect and transport signed journal records, but owns
// NONE of their signing keys. The forged-attestation fault deliberately keeps
// every writer/schema/root field correct and signs with the coordinator's key.
internal sealed class InfisicalMetadataPermissionFixtureSource(InfisicalMetadataPermissionFixture provider) :
    HttpMessageHandler
{
    private readonly ECDsa coordinator = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    internal InfisicalMetadataPermissionSource CreateClient() =>
        new(new(provider.Input().Observer, this, length =>
        {
            var buffer = new byte[length]; provider.Copies.Add(buffer); return buffer;
        }), "metadata-coordinator", MetadataPermissionSourceKind.ControlledFixture);
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (request.Headers.Authorization?.Parameter != "coordinator-token")
            return new(HttpStatusCode.Forbidden);
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token);
        provider.Copies.Add(bytes);
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var body = document.RootElement;
            NativeRunProtocol.RejectDuplicates(body);
            var root = body.GetProperty("root").Deserialize<MetadataPermissionRoot>(MetadataPermissionContract.Options)!;
            object facts;
            if (request.RequestUri!.AbsolutePath == "/metadata-permission/step")
            {
                var step = (MetadataPermissionStep)body.GetProperty("step").GetInt32();
                var packet = provider.Step(root, step, body.TryGetProperty("capability", out var cap) ? cap.GetString() : null);
                if (provider.Fault == "coordinator-forged-attestation" && step == MetadataPermissionStep.ObserveBefore &&
                    packet.Decisions.Length != 0)
                {
                    var signed = packet.Decisions[0];
                    byte[] content = MetadataPermissionContract.Bytes(signed.Content);
                    try
                    {
                        packet.Decisions[0] = signed with
                        {
                            Signature = Convert.ToBase64String(coordinator.SignData(content,
                            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                        };
                    }
                    finally { CryptographicOperations.ZeroMemory(content); }
                }
                if (provider.Fault == "content-tamper" && step == MetadataPermissionStep.Settle && packet.Commits.Length != 0)
                    packet.Commits[0] = packet.Commits[0] with
                    { Content = packet.Commits[0].Content with { PolicyHash = "changed-without-signature" } };
                if (provider.Fault == "strip-commit" && step == MetadataPermissionStep.Settle)
                    packet = packet with { Commits = [] };
                facts = packet;
            }
            else if (request.RequestUri.AbsolutePath == "/metadata-permission/measure")
                facts = provider.Measure(root, body.GetProperty("lease").GetGuid(),
                    body.GetProperty("username").GetString()!, body.GetProperty("password").GetString()!,
                    (MetadataPermissionAction)body.GetProperty("action").GetInt32());
            else return new(HttpStatusCode.NotFound);
            byte[] response = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                nonce = body.GetProperty("nonce").GetString(),
                observerIdentity = "metadata-coordinator",
                observedAt = DateTimeOffset.UtcNow,
                facts
            }, MetadataPermissionContract.Options);
            provider.Copies.Add(response);
            return new(HttpStatusCode.OK) { Content = new ClearingContent(response) };
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing) coordinator.Dispose();
        base.Dispose(disposing);
    }
    private sealed class ClearingContent : ByteArrayContent
    {
        private readonly byte[] bytes;
        internal ClearingContent(byte[] bytes) : base(bytes) => this.bytes = bytes;
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing) CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
