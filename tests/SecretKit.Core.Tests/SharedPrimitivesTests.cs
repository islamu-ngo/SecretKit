using SecretKit.Internal;

namespace SecretKit.Core.Tests;

public sealed class SharedPrimitivesTests
{
    [Test]
    [Arguments(1023, false)]
    [Arguments(1024, true)]
    [Arguments(16777216, true)]
    [Arguments(16777217, false)]
    public async Task TransferBoundsAdmitOnlySupportedByteBudgets(int bytes, bool valid)
    {
        await Assert.That(TransferLimits.IsValidByteBudget(bytes)).IsEqualTo(valid);
    }

    [Test]
    [Arguments(0, false)]
    [Arguments(1, true)]
    [Arguments(60000, true)]
    [Arguments(60001, false)]
    public async Task TransferTimeoutIsPositiveAndBounded(int milliseconds, bool valid)
    {
        await Assert.That(TransferLimits.IsValidTimeout(TimeSpan.FromMilliseconds(milliseconds))).IsEqualTo(valid);
    }

    [Test]
    public async Task ClosingDrainRejectsAdmissionAndWaitsForEveryLease()
    {
        var drain = new AsyncOperationDrain();
        IDisposable first = drain.Enter();
        IDisposable second = drain.Enter();
        Task closing = drain.Close();
        await Assert.That(ReferenceEquals(closing, drain.Close())).IsTrue();
        await Assert.That(closing.IsCompleted).IsFalse();
        await Assert.That(() => drain.Enter()).Throws<ObjectDisposedException>();
        first.Dispose();
        first.Dispose();
        await Assert.That(closing.IsCompleted).IsFalse();
        second.Dispose();
        await closing.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StreamDetectsOverflowWithoutReadingPastOneProbeByte(bool asynchronous)
    {
        using var input = new MemoryStream([1, 2, 3, 4, 5]);
        using var bounded = new BoundedResponseStream(input, 3);
        byte[] buffer = new byte[3];
        int count = asynchronous ? await bounded.ReadAsync(buffer.AsMemory()) : bounded.Read(buffer);
        await Assert.That(count).IsEqualTo(3);
        await Assert.That(buffer.SequenceEqual(new byte[] { 1, 2, 3 })).IsTrue();
        if (asynchronous)
            await Assert.That(async () => await bounded.ReadAsync(buffer.AsMemory())).Throws<ResponseBudgetExceededException>();
        else
            await Assert.That(() => bounded.Read(buffer)).Throws<ResponseBudgetExceededException>();
        await Assert.That(input.Position).IsEqualTo(4);
        await Assert.That(() => bounded.Read(buffer)).Throws<ResponseBudgetExceededException>();
        await Assert.That(input.Position).IsEqualTo(4);
    }

    [Test]
    public async Task ExactBudgetAllowsEofAndHonorsCallerCancellation()
    {
        using var bounded = new BoundedResponseStream(new MemoryStream([1, 2, 3]), 3);
        byte[] buffer = new byte[8];
        await Assert.That(await bounded.ReadAsync(buffer.AsMemory())).IsEqualTo(3);
        await Assert.That(await bounded.ReadAsync(buffer.AsMemory())).IsEqualTo(0);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.That(async () => await bounded.ReadAsync(buffer.AsMemory(), canceled.Token))
            .Throws<OperationCanceledException>();
    }

    [Test]
    public async Task JsonBudgetCountsActualBytesWithoutOverflowingOnHostileLength()
    {
        using var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new ByteArrayContent("{}"u8.ToArray())
        };
        response.Content.Headers.ContentLength = long.MaxValue;
        int observed = 0;

        using var document = await BoundedJson.ReadJsonAsync(response, 1024, 32,
            onChunkRead: count => { observed += count; return true; });

        await Assert.That(document).IsNotNull();
        await Assert.That(observed).IsEqualTo(2);
    }

    [Test]
    public async Task SafeSocketsDisableAmbientNetworkingFeatures()
    {
        using var handler = SecretKitSocketsHandlerFactory.Create();
        await Assert.That(handler.AllowAutoRedirect).IsFalse();
        await Assert.That(handler.UseCookies).IsFalse();
        await Assert.That(handler.UseProxy).IsFalse();
        await Assert.That(handler.ActivityHeadersPropagator).IsNull();
        await Assert.That(handler.PooledConnectionLifetime).IsEqualTo(TimeSpan.FromMinutes(2));
    }

    [Test]
    public async Task SelectedProviderOriginKeepsExplicitPrivateAndDevelopmentTrust()
    {
        OriginPolicy.ValidateProviderOrigin(new Uri("https://vault.internal:8443/"), false, false);
        OriginPolicy.ValidateProviderOrigin(new Uri("http://localhost:8080/"), false, true);
        OriginPolicy.ValidateProviderOrigin(new Uri("http://vault.internal/"), true, false);
        await Assert.That(() => OriginPolicy.ValidateProviderOrigin(new Uri("http://vault.internal/"), false, true))
            .Throws<ArgumentException>();
        await Assert.That(() => OriginPolicy.ValidatePublicWebhookEndpoint(new Uri("https://vault.example.test/events")))
            .ThrowsNothing();
    }
}
