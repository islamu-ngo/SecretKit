using System.Net;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class NativeFeedTests
{
    [Test]
    public async Task NativePutCarriesExactlyTheVerifiedArchiveAndRequiredProtocol()
    {
        byte[] package = ArchiveTests.Zip(("a", "test"));
        using var transport = new Transport(async (request, token) =>
        {
            await Assert.That(request.Method).IsEqualTo(HttpMethod.Put);
            await Assert.That(request.RequestUri!.AbsoluteUri).IsEqualTo("https://www.nuget.org/api/v2/package");
            await Assert.That(request.Headers.GetValues("X-NuGet-Protocol-Version").Single()).IsEqualTo("4.1.0");
            await Assert.That(request.Headers.Contains("X-NuGet-Client-Version")).IsFalse();
            await Assert.That(request.Headers.GetValues("X-NuGet-ApiKey").Single()).IsEqualTo("synthetic-test-key");
            await Assert.That(request.VersionPolicy).IsEqualTo(HttpVersionPolicy.RequestVersionExact);
            var body = (MultipartFormDataContent)request.Content!;
            await Assert.That(body.Count()).IsEqualTo(1);
            await Assert.That((await body.Single().ReadAsByteArrayAsync(token)).SequenceEqual(package)).IsTrue();
            return new HttpResponseMessage(HttpStatusCode.Created);
        });
        NativeFeed feed = Feed(transport);
        await Assert.That(await feed.PushAsync(Manifest.PackageIds[0], package, CancellationToken.None)).IsTrue();
    }

    [Test]
    [Arguments(409)]
    [Arguments(429)]
    [Arguments(500)]
    [Arguments(302)]
    public async Task FailureOrRedirectIsNotReplayed(int status)
    {
        int received = 0;
        using var transport = new Transport((_, _) =>
        {
            received++;
            return Task.FromResult(new HttpResponseMessage((HttpStatusCode)status));
        });
        await Assert.That(await Feed(transport).PushAsync(Manifest.PackageIds[0], [1], CancellationToken.None)).IsFalse();
        await Assert.That(received).IsEqualTo(1);
    }

    [Test]
    public async Task NativeReadDoesNotSendPublishingAuthorityAndOnly404MeansAbsent()
    {
        using var transport = new Transport(async (request, _) =>
        {
            await Assert.That(request.Headers.Contains("X-NuGet-ApiKey")).IsFalse();
            await Assert.That(request.RequestUri!.AbsoluteUri).IsEqualTo(
                "https://api.nuget.org/v3-flatcontainer/secretkit.core/0.1.0-preview.1/secretkit.core.0.1.0-preview.1.nupkg");
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });
        await Assert.That(await Feed(transport).DownloadAsync(Manifest.PackageIds[0], TestBundle.Version, CancellationToken.None))
            .IsNull();
        using var denied = new Transport((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden)));
        await Assert.That(() => Feed(denied).DownloadAsync(Manifest.PackageIds[0], TestBundle.Version, CancellationToken.None))
            .Throws<ReleaseException>();
    }

    [Test]
    public async Task ExcessiveResponseAndTransportFailureFailClosed()
    {
        using var transport = new Transport((_, _) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent([1]) };
            response.Content.Headers.ContentLength = PackageArchive.MaximumBytes + 1;
            return Task.FromResult(response);
        });
        await Assert.That(() => Feed(transport).DownloadAsync(Manifest.PackageIds[0], TestBundle.Version, CancellationToken.None))
            .Throws<ReleaseException>();
        using var broken = new Transport((_, _) => throw new HttpRequestException("synthetic wire failure"));
        await Assert.That(() => Feed(broken).PushAsync(Manifest.PackageIds[0], [1], CancellationToken.None))
            .Throws<HttpRequestException>();
    }

    private static NativeFeed Feed(HttpMessageHandler handler) => new(new string('a', 64), "test-owner", "synthetic-test-key")
    {
        ClientFactory = () => new HttpClient(handler, disposeHandler: false)
    };

    private sealed class Transport(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }
}
