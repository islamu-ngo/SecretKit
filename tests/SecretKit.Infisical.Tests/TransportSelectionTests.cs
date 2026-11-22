using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace SecretKit.Infisical.Tests;

public sealed class TransportSelectionTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SerializingTransportSelectionDoesNotTraverseBorrowedResources(bool borrowClient)
    {
        using var handler = new HostHandler();
        using var client = new HttpClient(handler, disposeHandler: false)
        {
            BaseAddress = new Uri("https://origin-canary.invalid/")
        };
        client.DefaultRequestHeaders.Add("X-Private-Setting", "header-canary");
        var selection = borrowClient
            ? InfisicalTransportOptions.HostControlled(client)
            : InfisicalTransportOptions.HostControlled(handler);

        string serialized = JsonSerializer.Serialize(selection);

        await Assert.That(serialized).IsEqualTo("{}");
    }

    [Test]
    public async Task TrustRootCopiesRemainPublicAndIndependentOfCallerCertificateLifetime()
    {
        using var key = ECDsa.Create();
        var request = new CertificateRequest("CN=private-root-canary", key, HashAlgorithmName.SHA256);
        using var original = request.CreateSelfSigned(DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddYears(100));
        byte[] expected = original.RawData;
        var selection = InfisicalTransportOptions.SafeWithPrivateTrust(original);
        original.Dispose();
        X509Certificate2[] first = selection.CopyRoots();
        foreach (var certificate in first) certificate.Dispose();

        X509Certificate2[] second = selection.CopyRoots();
        try
        {
            await Assert.That(second.Length).IsEqualTo(1);
            await Assert.That(second[0].RawData).IsEquivalentTo(expected);
            await Assert.That(second[0].HasPrivateKey).IsFalse();
            await Assert.That(JsonSerializer.Serialize(selection)).IsEqualTo("{}");
        }
        finally
        {
            foreach (var certificate in second) certificate.Dispose();
        }
    }

    private sealed class HostHandler : HttpMessageHandler
    {
        public string PrivateSetting => "pipeline-canary";

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
    }
}
