using System.Net;
using System.Text;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class InfisicalMutationOperationTests
{
    [Test]
    public async Task PredispatchRecoveryRetainsReceiptAndDispatchedWritesCannotReplay()
    {
        var tokens = new Tokens { Fail = true };
        using var wire = new Wire();
        await using var client = new InfisicalClient(new("https://service.test"), tokens, new(), null, wire);
        using var value = SecretMaterial.FromText("value-canary");
        var operation = client.PrepareCreate(new(client.Authority, new InfisicalSecretAddress("p", "e", "/", "k")), value);
        Guid receiptId = operation.Receipt.LocalId;
        await Assert.That((await operation.ExecuteAsync()).Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(operation.Receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        tokens.Fail = false;
        await Assert.That((await operation.ExecuteAsync()).IsSuccess).IsTrue();
        await Assert.That(operation.Receipt.LocalId).IsEqualTo(receiptId);
        await Assert.That(operation.Receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(async () => await operation.ExecuteAsync()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ConcurrentExecutionsAreRejectedAndLostResponsesRemainUnreplayable()
    {
        using var wire = new Wire { Hold = true };
        await using var client = new InfisicalClient(new("https://service.test"), new Tokens(), new(), null, wire);
        using var value = SecretMaterial.FromText("value-canary");
        var operation = client.PrepareUpdateValue(new(client.Authority, new InfisicalSecretAddress("p", "e", "/", "k")), value);
        Task<SecretOutcome<InfisicalStaticChange>> pending = operation.ExecuteAsync().AsTask();
        await wire.Entered.Task;
        try
        {
            await Assert.That(async () => await operation.ExecuteAsync()).Throws<InvalidOperationException>();
        }
        finally { wire.Release.SetResult(); }
        await Assert.That((await pending).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(operation.Receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(async () => await operation.ExecuteAsync()).Throws<InvalidOperationException>();
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Fail { get; set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(Fail ? SecretOutcome<InfisicalAccessToken>.Failure(SecretStatus.Unavailable) :
                SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("token-canary"))));
    }
    private sealed class Wire : HttpMessageHandler
    {
        public bool Hold { get; init; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Entered.TrySetResult();
            if (Hold)
            {
                await Release.Task.WaitAsync(cancellationToken);
                throw new HttpRequestException("Lost response.");
            }
            return new(HttpStatusCode.OK) { Content = new StringContent("{\"secret\":{\"secretKey\":\"k\",\"workspace\":\"p\",\"environment\":\"e\",\"version\":1}}", Encoding.UTF8, "application/json") };
        }
    }
}
