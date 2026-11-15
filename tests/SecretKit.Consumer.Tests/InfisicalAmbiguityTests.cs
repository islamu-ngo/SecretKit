using System.Net;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;
using SecretKit.Infisical;

namespace SecretKit.Consumer.Tests;

public sealed class InfisicalAmbiguityTests
{
    [Test]
    public async Task PreparedConfigurationPreservesProtectedProviderFailureContext()
    {
        using var wire = new Wire { Reject = true };
        await using var client = new InfisicalClient(new("https://api.test"), new Tokens(),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) });
        var reference = new SecretReference(client.Authority, new InfisicalSecretAddress("project", "test", "/", "key"));
        using var loader = new SecretSnapshotLoader(
            [new SecretSelection("selected", client, reference, SecretPresencePolicy.Optional)]);
        var collected = await loader.RefreshAsync();
        await Assert.That(collected.CorrelationId?.Reveal()).IsEqualTo("prepared-correlation");

        var result = await PreparedSecretConfiguration.PrepareAsync(
            [new SecretSelection("selected", client, reference, SecretPresencePolicy.Optional)]);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.PermissionDenied);
        await Assert.That(result.CorrelationId?.Reveal()).IsEqualTo("prepared-correlation");
    }

    [Test]
    public async Task Concealed404CannotPublishOptionalAbsenceOrReplaceValidGeneration()
    {
        using var wire = new Wire();
        await using var client = new InfisicalClient(new("https://api.test"), new Tokens(),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) });
        var reference = new SecretReference(client.Authority, new InfisicalSecretAddress("project", "test", "/", "key"));
        using var loader = new SecretSnapshotLoader([new SecretSelection("selected", client, reference, SecretPresencePolicy.Optional)]);
        await loader.RefreshAsync();
        using var previous = loader.Acquire();
        wire.Conceal = true;

        var result = await loader.RefreshAsync();

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        using var current = loader.Acquire();
        await Assert.That(current.Generation).IsEqualTo(previous.Generation);
        using var retained = current.Read("selected");
        await Assert.That(retained.Material.Reveal()).IsEqualTo("valid-generation");
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("token"))));
    }

    private sealed class Wire : HttpMessageHandler
    {
        internal bool Conceal { get; set; }
        internal bool Reject { get; init; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(Reject ? HttpStatusCode.Forbidden : Conceal ? HttpStatusCode.NotFound : HttpStatusCode.OK)
            {
                Content = new StringContent(Reject
                    ? """{"error":"ForbiddenError","reqId":"prepared-correlation"}"""
                    : Conceal
                    ? """{"statusCode":404,"error":"NotFound"}"""
                    : """{"secret":{"secretKey":"key","secretValueHidden":false,"secretValue":"valid-generation"}}""")
            });
    }
}
