using SecretKit.Core;
using SecretKit.Extensions.Configuration;

namespace SecretKit.Configuration.Tests;

public sealed class SecretGenerationCoordinatorTests
{
    [Test]
    public async Task ReplacementRetiresClientOnlyAfterLastLeaseAndRejectsAcquisitionAfterDisposal()
    {
        var clients = new List<Client>();
        var coordinator = Create((_, _) =>
        {
            var client = new Client();
            clients.Add(client);
            return ValueTask.FromResult(SecretOutcome<Client>.Success(client));
        });
        await coordinator.EnableAsync();
        SecretGenerationLease<Client> old = coordinator.Acquire()!;
        await coordinator.EnableAsync();
        await Assert.That(clients[0].Disposals).IsEqualTo(0);
        await old.DisposeAsync();
        await old.DisposeAsync();
        await Assert.That(clients[0].Disposals).IsEqualTo(1);
        await coordinator.DisposeAsync();
        await Assert.That(clients[1].Disposals).IsEqualTo(1);
        await Assert.That(() => coordinator.Acquire()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task CallbackCanDisableAndReleaseLeaseWithoutRetiringItsInFlightClient()
    {
        var client = new Client();
        await using var coordinator = Create((_, _) =>
            ValueTask.FromResult(SecretOutcome<Client>.Success(client)));
        await coordinator.EnableAsync();
        SecretGenerationLease<Client> lease = coordinator.Acquire()!;
        int result = await lease.ExecuteAsync(async (borrowed, _) =>
        {
            await coordinator.DisableAsync();
            await lease.DisposeAsync();
            await Assert.That(borrowed.Disposals).IsEqualTo(0);
            return 42;
        });
        await Assert.That(result).IsEqualTo(42);
        await Assert.That(client.Disposals).IsEqualTo(1);
        await Assert.That(async () => await lease.ExecuteAsync(static (_, _) => ValueTask.FromResult(0)))
            .Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task ConcurrentLeaseDisposalWaitsForCallbackPinBeforeRetirement()
    {
        var client = new Client();
        await using var coordinator = Create((_, _) =>
            ValueTask.FromResult(SecretOutcome<Client>.Success(client)));
        await coordinator.EnableAsync();
        SecretGenerationLease<Client> lease = coordinator.Acquire()!;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<int> operation = lease.ExecuteAsync(async (borrowed, _) =>
        {
            entered.SetResult();
            await resume.Task;
            await Assert.That(borrowed.Disposals).IsEqualTo(0);
            return 7;
        }).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await coordinator.DisableAsync();
        await lease.DisposeAsync();
        await Assert.That(client.Disposals).IsEqualTo(0);
        resume.SetResult();
        await Assert.That(await operation).IsEqualTo(7);
        await Assert.That(client.Disposals).IsEqualTo(1);
    }

    [Test]
    public async Task CallbackFailureReleasesOperationPinAndCancellationDoesNotRunCallback()
    {
        var client = new Client();
        await using var coordinator = Create((_, _) =>
            ValueTask.FromResult(SecretOutcome<Client>.Success(client)));
        await coordinator.EnableAsync();
        SecretGenerationLease<Client> lease = coordinator.Acquire()!;
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        bool entered = false;
        await Assert.That(async () => await lease.ExecuteAsync((_, _) =>
        {
            entered = true;
            return ValueTask.FromResult(0);
        }, cancellation.Token)).Throws<OperationCanceledException>();
        await Assert.That(entered).IsFalse();
        await Assert.That(async () => await lease.ExecuteAsync<int>(async (_, _) =>
        {
            await coordinator.DisableAsync();
            await lease.DisposeAsync();
            throw new ArgumentException("Application callback failed.");
        })).Throws<ArgumentException>();
        await Assert.That(client.Disposals).IsEqualTo(1);
    }

    [Test]
    public async Task CheckOnlyCandidateIsDisposedAndRetirementFailureFailsClosedWithoutLeakingDetails()
    {
        var client = new Client { FailDisposal = true };
        var coordinator = Create((_, _) =>
            ValueTask.FromResult(SecretOutcome<Client>.Success(client)));
        SecretGenerationObservation observation = await coordinator.CheckAgainAsync();
        await Assert.That(observation.Active).IsFalse();
        await Assert.That(observation.LastStatus).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(client.Disposals).IsEqualTo(1);
        try
        {
            await coordinator.DisposeAsync();
            throw new Exception("Expected retirement failure.");
        }
        catch (InvalidOperationException exception)
        {
            await Assert.That(exception.ToString().Contains("canary-disposal-detail", StringComparison.Ordinal)).IsFalse();
        }
    }

    [Test]
    public async Task SelectedMappingLimitRejectsConstructionBeforeReading()
    {
        var reader = new Reader();
        await Assert.That(() => Controlled(reader, new(maximumSelections: 1), TimeProvider.System))
            .Throws<ArgumentException>();
        await Assert.That(reader.Reads).IsEqualTo(0);
    }

    [Test]
    public async Task SelectedConcurrencyAdmitsTwoReadsBeforeEitherCompletes()
    {
        var both = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int entered = 0;
        var reader = new Reader
        {
            BeforeRead = async _ =>
            {
                if (Interlocked.Increment(ref entered) == 2) both.SetResult();
                await release.Task;
            }
        };
        await using var coordinator = Controlled(reader, new(maximumConcurrency: 2), TimeProvider.System);
        var pending = coordinator.EnableAsync().AsTask();
        try
        {
            await both.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.That(pending.IsCompleted).IsFalse();
        }
        finally { release.TrySetResult(); }
        await Assert.That((await pending.WaitAsync(TimeSpan.FromSeconds(10))).Active).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SelectedPayloadLimitPreventsCandidateActivation(bool checkOnly)
    {
        var reader = new Reader { Text = new string('x', 2000) };
        await using var coordinator = Controlled(reader, new(maximumMaterialBytes: 1024), TimeProvider.System);
        var result = await (checkOnly ? coordinator.CheckAgainAsync() : coordinator.EnableAsync());
        await Assert.That(result.LastStatus).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(coordinator.Acquire()).IsNull();
        await Assert.That(() => reader.LastMaterial!.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SelectedDeadlineRejectsLateReaderForEitherCollectionEntrypoint(bool checkOnly)
    {
        var time = new CollectionTime();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reader = new Reader
        {
            BeforeRead = async _ => { entered.TrySetResult(); await release.Task; }
        };
        await using var coordinator = Controlled(reader, new(collectionTimeout: TimeSpan.FromSeconds(2)), time);
        var pending = (checkOnly ? coordinator.CheckAgainAsync() : coordinator.EnableAsync()).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        time.Advance(TimeSpan.FromSeconds(3));
        release.SetResult();
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(result.LastStatus).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(coordinator.Acquire()).IsNull();
        await Assert.That(() => reader.LastMaterial!.Reveal()).Throws<ObjectDisposedException>();
    }

    private static SecretGenerationCoordinator<Client> Controlled(Reader reader,
        SecretCollectionOptions options, TimeProvider time) => new(reader,
            new Dictionary<string, SecretReference>
            {
                ["first"] = new(reader.Authority, new Address()),
                ["second"] = new(reader.Authority, new Address())
            }, static (_, _) => ValueTask.FromResult(SecretOutcome<Client>.Success(new Client())),
            SecretGenerationStalePolicy.FailClosed, TimeSpan.FromHours(1), time, options);

    private static SecretGenerationCoordinator<Client> Create(
        Func<SecretSnapshotHandle, CancellationToken, ValueTask<SecretOutcome<Client>>> validate)
    {
        var reader = new Reader();
        return new(reader, new Dictionary<string, SecretReference>
        {
            ["required"] = new(reader.Authority, new Address())
        }, validate, SecretGenerationStalePolicy.FailClosed, TimeSpan.FromHours(1), TimeProvider.System);
    }

    private sealed class Client : IAsyncDisposable
    {
        public int Disposals { get; private set; }
        public bool FailDisposal { get; init; }
        public ValueTask DisposeAsync()
        {
            Disposals++;
            if (FailDisposal) throw new InvalidOperationException("canary-disposal-detail");
            return ValueTask.CompletedTask;
        }
    }

    private sealed class Address : SecretAddress;
    private sealed class Reader : ISecretReader
    {
        private int _reads;
        internal int Reads => Volatile.Read(ref _reads);
        internal string Text { get; init; } = "synthetic-value";
        internal SecretMaterial? LastMaterial { get; private set; }
        internal Func<CancellationToken, Task>? BeforeRead { get; init; }
        public SecretAuthority Authority { get; } = new();
        public async ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref _reads);
            if (BeforeRead is not null) await BeforeRead(cancellationToken);
            var material = SecretMaterial.FromText(Text);
            LastMaterial = material;
            return SecretOutcome<SecretRead>.Success(new(material,
                new SecretObservation(reference, null, DateTimeOffset.UtcNow, SecretValidity.Valid)));
        }
    }
}
