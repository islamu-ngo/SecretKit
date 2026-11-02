using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Coordinator credential alone does not permit writer signatures.
internal sealed class InfisicalTemplatePrincipalFixtureSource(InfisicalTemplatePrincipalFixture fixture) : HttpMessageHandler
{
    private readonly ECDsa coordinator = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    internal InfisicalTemplatePrincipalSource CreateClient() =>
        new(new(fixture.Input().Observer, this, length =>
        {
            byte[] bytes = new byte[length]; fixture.Copies.Add(bytes); return bytes;
        }), "principal-coordinator", TemplatePrincipalKind.ControlledFixture);
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (request.Headers.Authorization?.Parameter != "coordinator-token") return new(HttpStatusCode.Forbidden);
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token); fixture.Copies.Add(bytes);
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var body = document.RootElement;
            NativeRunProtocol.RejectDuplicates(body);
            var root = body.GetProperty("root").Deserialize<TemplatePrincipalRoot>(TemplatePrincipalContract.Options)!;
            var step = (TemplatePrincipalStep)body.GetProperty("step").GetInt32();
            var packet = await fixture.StepAsync(root, step, body.TryGetProperty("capability", out var cap) ? cap.GetString() : null,
                body.TryGetProperty("receipt", out var receipt) ? receipt.Deserialize<TemplatePrincipalReceipt>(
                    TemplatePrincipalContract.Options) : null, token);
            if (fixture.Fault == "lost-reserve" && step == TemplatePrincipalStep.Reserve)
                throw new NativeCaseFailureException("observer-unavailable");
            if (fixture.Fault == "coordinator-forgery" && step == TemplatePrincipalStep.ObserveBefore)
            {
                byte[] payload = TemplatePrincipalContract.Bytes(packet.Memberships.Payload);
                try
                {
                    packet = packet with
                    {
                        Memberships = packet.Memberships with
                        {
                            Signature = Convert.ToBase64String(coordinator.SignData(payload, HashAlgorithmName.SHA256,
                                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                        }
                    };
                }
                finally { CryptographicOperations.ZeroMemory(payload); }
            }
            byte[] response = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                nonce = body.GetProperty("nonce").GetString(),
                observerIdentity = "principal-coordinator",
                observedAt = DateTimeOffset.UtcNow,
                facts = packet
            }, TemplatePrincipalContract.Options);
            fixture.Copies.Add(response);
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
