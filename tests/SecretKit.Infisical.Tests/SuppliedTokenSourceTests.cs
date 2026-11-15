using System.Net;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class SuppliedTokenSourceTests
{
    [Test]
    public async Task InputSourceAndReturnedCopiesHaveIndependentLifetimes()
    {
        using var input = SecretMaterial.FromText("supplied-canary");
        using var source = new InfisicalSuppliedTokenSource(input);
        input.Dispose();
        using var first = (await source.GetTokenAsync(CancellationToken.None)).Value;
        first.Dispose();
        using var second = (await source.GetTokenAsync(CancellationToken.None)).Value;
        source.Dispose();
        source.Dispose();

        await Assert.That(second.Material.Reveal()).IsEqualTo("supplied-canary");
        await Assert.That(second.ExpiresAt).IsNull();
        await Assert.That(async () => await source.GetTokenAsync(CancellationToken.None))
            .Throws<ObjectDisposedException>();
        await Assert.That(JsonSerializer.Serialize(source).Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(source.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task SourceDisposalPreservesBorrowedInput()
    {
        using var input = SecretMaterial.FromText("borrowed-canary");
        using var source = new InfisicalSuppliedTokenSource(input);
        source.Dispose();

        await Assert.That(input.Reveal()).IsEqualTo("borrowed-canary");
    }

    [Test]
    public async Task CancellationDoesNotConsumeSourceMaterial()
    {
        using var input = SecretMaterial.FromText("cancel-canary");
        using var source = new InfisicalSuppliedTokenSource(input);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.That(async () => await source.GetTokenAsync(cancellation.Token))
            .Throws<OperationCanceledException>();
        using var token = (await source.GetTokenAsync(CancellationToken.None)).Value;
        await Assert.That(token.Material.Reveal()).IsEqualTo("cancel-canary");
    }

    [Test]
    [Arguments(-1)]
    [Arguments(0)]
    [Arguments(1)]
    public async Task HostExpiryRejectsAtAndAfterDeadline(int secondsAfterExpiry)
    {
        var clock = new Clock();
        DateTimeOffset expiry = clock.Now;
        using var input = SecretMaterial.FromText("expiry-canary");
        using var source = new InfisicalSuppliedTokenSource(input, expiry, clock);
        clock.Now = expiry.AddSeconds(secondsAfterExpiry);

        var result = await source.GetTokenAsync(CancellationToken.None);
        using var token = result.IsSuccess ? result.Value : null;
        await Assert.That(result.Status).IsEqualTo(secondsAfterExpiry < 0 ? SecretStatus.Success : SecretStatus.Expired);
        if (token is not null)
            await Assert.That(token.ExpiresAt).IsEqualTo(expiry);
        else
        {
            await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.CredentialUnavailable);
            await Assert.That(() => result.Value).Throws<InvalidOperationException>();
        }
    }

    [Test]
    public async Task UnobservedExpiryDoesNotBecomeLocalExpiration()
    {
        var clock = new Clock { Now = DateTimeOffset.MaxValue };
        using var input = SecretMaterial.FromText("opaque-canary");
        using var source = new InfisicalSuppliedTokenSource(input, timeProvider: clock);

        using var token = (await source.GetTokenAsync(CancellationToken.None)).Value;
        await Assert.That(token.ExpiresAt).IsNull();
        await Assert.That(token.Material.Reveal()).IsEqualTo("opaque-canary");
    }

    [Test]
    public async Task LocalExpirationDoesNotDisposePreviouslyReturnedToken()
    {
        var clock = new Clock();
        DateTimeOffset expiry = clock.Now.AddMinutes(1);
        using var input = SecretMaterial.FromText("retained-canary");
        using var source = new InfisicalSuppliedTokenSource(input, expiry, clock);
        using var token = (await source.GetTokenAsync(CancellationToken.None)).Value;
        clock.Now = expiry;

        var result = await source.GetTokenAsync(CancellationToken.None);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Expired);
        await Assert.That(token.Material.Reveal()).IsEqualTo("retained-canary");
    }

    [Test]
    public async Task DisposalBeforeCopyAdmissionRejectsInFlightCall()
    {
        using var clock = new BlockingClock();
        using var input = SecretMaterial.FromText("race-canary");
        using var source = new InfisicalSuppliedTokenSource(input, DateTimeOffset.MaxValue, clock);
        Task<SecretOutcome<InfisicalAccessToken>> pending = Task.Run(async () =>
            await source.GetTokenAsync(CancellationToken.None));
        try
        {
            await clock.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            source.Dispose();
        }
        finally
        {
            clock.Release.Set();
        }

        await Assert.That(async () => await pending).Throws<ObjectDisposedException>();
        await Assert.That(input.Reveal()).IsEqualTo("race-canary");
    }

    [Test]
    public async Task CancellationBeforeCopyAdmissionRejectsInFlightCall()
    {
        using var clock = new BlockingClock();
        using var input = SecretMaterial.FromText("race-canary");
        using var source = new InfisicalSuppliedTokenSource(input, DateTimeOffset.MaxValue, clock);
        using var cancellation = new CancellationTokenSource();
        Task<SecretOutcome<InfisicalAccessToken>> pending = Task.Run(async () =>
            await source.GetTokenAsync(cancellation.Token));
        try
        {
            await clock.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();
        }
        finally
        {
            clock.Release.Set();
        }

        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task ExistingClientUsesCopiesWithoutOwningSourceOrInput()
    {
        using var input = SecretMaterial.FromText("client-canary");
        using var source = new InfisicalSuppliedTokenSource(input);
        using var wire = new Wire();
        await using var client = new InfisicalClient(new("https://supplied.test"), source,
            new InfisicalNetworkOptions(), null, wire);
        var reference = new SecretReference(client.Authority,
            new InfisicalSecretAddress("project", "test", "/", "key"));

        using var first = (await client.ReadAsync(reference)).Value;
        using var second = (await client.ReadAsync(reference)).Value;
        await client.DisposeAsync();
        using var token = (await source.GetTokenAsync(CancellationToken.None)).Value;
        source.Dispose();

        await Assert.That(first.Material.Reveal()).IsEqualTo("selected-value");
        await Assert.That(second.Material.Reveal()).IsEqualTo("selected-value");
        await Assert.That(token.Material.Reveal()).IsEqualTo("client-canary");
        await Assert.That(input.Reveal()).IsEqualTo("client-canary");
    }

    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 11, 15, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class BlockingClock : TimeProvider, IDisposable
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ManualResetEventSlim Release { get; } = new();
        public override DateTimeOffset GetUtcNow()
        {
            Entered.TrySetResult();
            if (!Release.Wait(TimeSpan.FromSeconds(5)))
                throw new TimeoutException("Token acquisition was not released.");
            return DateTimeOffset.UnixEpoch;
        }
        public void Dispose() => Release.Dispose();
    }

    private sealed class Wire : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method != HttpMethod.Get || request.Headers.Authorization?.Parameter != "client-canary")
                throw new InvalidOperationException("Unexpected fixture request.");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""
                    {"secret":{"secretKey":"key","secretValue":"selected-value","secretValueHidden":false,"version":1}}
                    """)
            });
        }
    }
}
