using System.Net;
using SecretKit.Infisical;

namespace SecretKit.Infisical.Management.Tests;

public sealed class TransportOwnershipTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DisposingManagementTransportPreservesBorrowedPipeline(bool borrowClient)
    {
        using var handler = new HostHandler();
        using var http = new HttpClient(handler, disposeHandler: false)
        {
            BaseAddress = new Uri("https://host.example/"),
            Timeout = TimeSpan.FromSeconds(19)
        };
        http.DefaultRequestHeaders.Add("X-Host-Setting", "retained");
        using (var transport = new ManagementTransport(new Uri("https://provider.example/"), new()
        {
            Transport = borrowClient
                ? InfisicalTransportOptions.HostControlled(http)
                : InfisicalTransportOptions.HostControlled(handler)
        })) { }

        using HttpResponseMessage response = await http.GetAsync("alive");
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(handler.Disposed).IsFalse();
        await Assert.That(http.BaseAddress).IsEqualTo(new Uri("https://host.example/"));
        await Assert.That(http.Timeout).IsEqualTo(TimeSpan.FromSeconds(19));
        await Assert.That(http.DefaultRequestHeaders.GetValues("X-Host-Setting").Single()).IsEqualTo("retained");
    }

    private sealed class HostHandler : HttpMessageHandler
    {
        public bool Disposed { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(Disposed, this);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
        }

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }
}
