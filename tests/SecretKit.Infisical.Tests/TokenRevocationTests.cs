using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class TokenRevocationTests
{
    [Test]
    public async Task ExactSelectedTokenIsAcknowledgedOnceWithoutExportingProviderProse()
    {
        using var token = SecretMaterial.FromText("selected-token-canary");
        var wire = new Wire(async (request, _) =>
        {
            await Assert.That(request.Method).IsEqualTo(HttpMethod.Post);
            await Assert.That(request.RequestUri!.AbsoluteUri).IsEqualTo("https://auth.test/api/v1/auth/token/revoke");
            await Assert.That(request.Headers.Authorization is null).IsTrue();
            using var json = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
            await Assert.That(json.RootElement.EnumerateObject().Count()).IsEqualTo(1);
            await Assert.That(json.RootElement.GetProperty("accessToken").GetString()).IsEqualTo("selected-token-canary");
            return Response(200, """{"message":"private-provider-prose"}""");
        });
        using var client = new InfisicalProofAuthentication(new("https://auth.test"), wire);
        var receipt = client.CreateRevocationReceipt();
        var status = await client.RevokeTokenAsync(token, receipt);
        await Assert.That(status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(JsonSerializer.Serialize(receipt).Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(await client.RevokeTokenAsync(token, receipt)).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Sends).IsEqualTo(1);
        await Assert.That(token.Reveal()).IsEqualTo("selected-token-canary");
    }

    [Test]
    [Arguments(401, "private", SecretStatus.Denied, DispatchEvidence.Rejected)]
    [Arguments(403, "private", SecretStatus.Denied, DispatchEvidence.Rejected)]
    [Arguments(400, "private", SecretStatus.Invalid, DispatchEvidence.Rejected)]
    [Arguments(422, "private", SecretStatus.Invalid, DispatchEvidence.Rejected)]
    [Arguments(429, "private", SecretStatus.Throttled, DispatchEvidence.Rejected)]
    [Arguments(500, "private", SecretStatus.Unknown, DispatchEvidence.PossiblyDispatched)]
    [Arguments(302, "private", SecretStatus.Unknown, DispatchEvidence.PossiblyDispatched)]
    [Arguments(200, "{}", SecretStatus.Unknown, DispatchEvidence.PossiblyDispatched)]
    [Arguments(200, "{\"message\":123}", SecretStatus.Unknown, DispatchEvidence.PossiblyDispatched)]
    [Arguments(200, "{\"message\":\"x\",\"extra\":\"canary\"}", SecretStatus.Unknown, DispatchEvidence.PossiblyDispatched)]
    [Arguments(200, "{\"message\":\"x\",\"message\":\"y\"}", SecretStatus.Unknown, DispatchEvidence.PossiblyDispatched)]
    public async Task StatusAndClosedAcknowledgementKeepUncertainty(int code, string body, SecretStatus expected, DispatchEvidence evidence)
    {
        using var token = SecretMaterial.FromText("selected");
        var wire = new Wire((_, _) => Task.FromResult(Response(code, body)));
        using var client = new InfisicalProofAuthentication(new("https://auth.test"), wire);
        var receipt = client.CreateRevocationReceipt();
        await Assert.That(await client.RevokeTokenAsync(token, receipt)).IsEqualTo(expected);
        await Assert.That(receipt.Evidence).IsEqualTo(evidence);
        await Assert.That(wire.Sends).IsEqualTo(1);
    }

    [Test]
    public async Task ForeignReceiptAndPreCancellationDoNotDispatch()
    {
        using var token = SecretMaterial.FromText("selected");
        var wire = new Wire((_, _) => throw new InvalidOperationException("Must not dispatch."));
        using var client = new InfisicalProofAuthentication(new("https://auth.test"), wire);
        using var other = new InfisicalProofAuthentication(new("https://auth.test"), wire);
        await Assert.That(await client.RevokeTokenAsync(token, other.CreateRevocationReceipt())).IsEqualTo(SecretStatus.Invalid);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var receipt = client.CreateRevocationReceipt();
        await Assert.That(async () => await client.RevokeTokenAsync(token, receipt, cancellation.Token)).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(wire.Sends).IsEqualTo(0);
    }

    [Test]
    public async Task CommittedLossNeverReplays()
    {
        using var token = SecretMaterial.FromText("selected");
        bool committed = false;
        var wire = new Wire((_, _) =>
        {
            committed = true;
            throw new HttpRequestException("private-provider-failure");
        });
        using var client = new InfisicalProofAuthentication(new("https://auth.test"), wire);
        var receipt = client.CreateRevocationReceipt();
        await Assert.That(await client.RevokeTokenAsync(token, receipt)).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(committed).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(await client.RevokeTokenAsync(token, receipt)).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Sends).IsEqualTo(1);
    }

    [Test]
    public async Task PostCommitCancellationPreservesUncertainty()
    {
        using var token = SecretMaterial.FromText("selected");
        using var cancellation = new CancellationTokenSource();
        var wire = new Wire((_, ct) =>
        {
            cancellation.Cancel();
            ct.ThrowIfCancellationRequested();
            throw new InvalidOperationException("Cancellation should propagate.");
        });
        using var client = new InfisicalProofAuthentication(new("https://auth.test"), wire);
        var receipt = client.CreateRevocationReceipt();
        await Assert.That(async () => await client.RevokeTokenAsync(token, receipt, cancellation.Token)).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(wire.Sends).IsEqualTo(1);
    }

    [Test]
    public async Task OversizedAcknowledgementRemainsUnknown()
    {
        using var token = SecretMaterial.FromText("selected");
        var wire = new Wire((_, _) => Task.FromResult(Response(200, "{\"message\":\"" + new string('x', 2048) + "\"}")));
        using var client = new InfisicalProofAuthentication(new("https://auth.test"), wire,
            new InfisicalNetworkOptions { MaximumResponseBytes = 1024 });
        var receipt = client.CreateRevocationReceipt();
        await Assert.That(await client.RevokeTokenAsync(token, receipt)).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    private static HttpResponseMessage Response(int status, string body) => new((HttpStatusCode)status)
    { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class Wire(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        public int Sends { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sends++;
            return send(request, cancellationToken);
        }
    }
}
