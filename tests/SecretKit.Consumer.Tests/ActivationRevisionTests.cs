using SecretKit.Core;
using SecretKit.Extensions.Configuration;
using SecretKit.Samples.RuntimeConfiguration;

namespace SecretKit.Consumer.Tests;

public sealed class ActivationRevisionTests
{
    [Test]
    public async Task RetirementSelectsAsynchronousCleanupForAnAsyncApplicationClient()
    {
        var fixture = new RuntimeFixture { Value = "prepared" };
        var client = new DualDisposalClient();
        await using var coordinator = new RuntimeIntegrationCoordinator(fixture.Reader,
            new Dictionary<string, SecretReference>
            {
                ["credential"] = new(fixture.Reader.Authority, new RuntimeFixture.Address())
            }, (_, _) => ValueTask.FromResult(SecretOutcome<IRuntimeIntegrationClient>.Success(client)),
            RuntimeStalePolicy.FailClosed, TimeSpan.FromMinutes(1), fixture.Time);
        await coordinator.EnableAsync();

        await coordinator.DisableAsync();

        await Assert.That(client.SynchronousDisposals).IsEqualTo(0);
        await Assert.That(client.AsynchronousDisposals).IsEqualTo(1);
    }

    private sealed class DualDisposalClient : IRuntimeIntegrationClient, IAsyncDisposable
    {
        internal int SynchronousDisposals;
        internal int AsynchronousDisposals;
        internal Func<ValueTask>? Cleanup;
        public ValueTask<string> ExecuteAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult("prepared");
        public void Dispose() => SynchronousDisposals++;
        public async ValueTask DisposeAsync()
        {
            Interlocked.Increment(ref AsynchronousDisposals);
            if (Cleanup is { } cleanup) await cleanup();
        }
    }

    [Test]
    public async Task BlockingAsyncRetirementDoesNotHoldTheCoordinatorGate()
    {
        var entered = RuntimeFixture.Signal();
        var release = RuntimeFixture.Signal();
        var client = new DualDisposalClient
        {
            Cleanup = async () => { entered.SetResult(); await release.Task; }
        };
        var fixture = new RuntimeFixture { Value = "prepared" };
        await using var coordinator = AsyncCoordinator(fixture, client);
        await coordinator.EnableAsync();
        Task disable = coordinator.DisableAsync().AsTask();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            RuntimeActivationObservation state = await Task.Run(coordinator.Observe)
                .WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.That(state.Active).IsFalse();
            await Assert.That(disable.IsCompleted).IsFalse();
        }
        finally { release.TrySetResult(); }
        await disable.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That(client.AsynchronousDisposals).IsEqualTo(1);
    }

    [Test]
    public async Task DisposalDrainsOutstandingLeasesDespiteCancelledWaiter()
    {
        var fixture = new RuntimeFixture { Value = "prepared" };
        var client = new DualDisposalClient();
        var coordinator = AsyncCoordinator(fixture, client);
        await coordinator.EnableAsync();
        RuntimeGenerationLease lease = coordinator.Acquire()!;
        Task stop = coordinator.DisposeAsync().AsTask();
        try
        {
            await Assert.That(() => coordinator.Acquire()).Throws<ObjectDisposedException>();
            await Assert.That(await lease.ExecuteAsync()).IsEqualTo("prepared");
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            await Assert.That(async () => await stop.WaitAsync(cancellation.Token))
                .Throws<OperationCanceledException>();
            await Assert.That(async () => await stop.WaitAsync(TimeSpan.Zero))
                .Throws<TimeoutException>();
            await Assert.That(client.AsynchronousDisposals).IsEqualTo(0);
        }
        finally { await lease.DisposeAsync(); }
        await stop.WaitAsync(TimeSpan.FromSeconds(5));
        await coordinator.DisposeAsync();
        await Assert.That(client.AsynchronousDisposals).IsEqualTo(1);
    }

    [Test]
    public async Task RejectedCandidateRetirementCompletesBeforeCancelledPreparationReturns()
    {
        var validating = RuntimeFixture.Signal();
        var releaseValidation = RuntimeFixture.Signal();
        var retiring = RuntimeFixture.Signal();
        var releaseRetirement = RuntimeFixture.Signal();
        var fixture = new RuntimeFixture { Value = "prepared" };
        var client = new DualDisposalClient
        {
            Cleanup = async () => { retiring.SetResult(); await releaseRetirement.Task; }
        };
        using var cancellation = new CancellationTokenSource();
        await using var coordinator = new RuntimeIntegrationCoordinator(fixture.Reader,
            new Dictionary<string, SecretReference>
            {
                ["credential"] = new(fixture.Reader.Authority, new RuntimeFixture.Address())
            }, async (_, _) =>
            {
                validating.SetResult();
                await releaseValidation.Task;
                return SecretOutcome<IRuntimeIntegrationClient>.Success(client);
            }, RuntimeStalePolicy.FailClosed, TimeSpan.FromMinutes(1), fixture.Time);
        Task preparation = coordinator.EnableAsync(cancellation.Token).AsTask();
        try
        {
            await validating.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();
            releaseValidation.SetResult();
            await retiring.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.That(preparation.IsCompleted).IsFalse();
            await Assert.That(coordinator.Acquire()).IsNull();
        }
        finally
        {
            releaseValidation.TrySetResult();
            releaseRetirement.TrySetResult();
        }
        await Assert.That(async () => await preparation.WaitAsync(TimeSpan.FromSeconds(5)))
            .Throws<OperationCanceledException>();
        await Assert.That(client.AsynchronousDisposals).IsEqualTo(1);
    }

    [Test]
    public async Task RetirementFailureIsObservedWithoutDisclosingClientException()
    {
        const string canary = "synthetic-disposal-exception-canary";
        var fixture = new RuntimeFixture { Value = "prepared" };
        var client = new DualDisposalClient
        {
            Cleanup = () => throw new InvalidOperationException(canary)
        };
        var coordinator = AsyncCoordinator(fixture, client);
        await coordinator.EnableAsync();
        InvalidOperationException? failure = null;
        try { await coordinator.DisableAsync(); }
        catch (InvalidOperationException exception) { failure = exception; }
        await Assert.That(failure).IsNotNull();
        await Assert.That(failure!.ToString().Contains(canary, StringComparison.Ordinal)).IsFalse();
        await Assert.That(coordinator.Observe().LastStatus).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(async () => await coordinator.DisposeAsync()).Throws<InvalidOperationException>();
        await Assert.That(client.AsynchronousDisposals).IsEqualTo(1);
    }

    private static RuntimeIntegrationCoordinator AsyncCoordinator(RuntimeFixture fixture,
        IRuntimeIntegrationClient client) =>
        new(fixture.Reader, new Dictionary<string, SecretReference>
        {
            ["credential"] = new(fixture.Reader.Authority, new RuntimeFixture.Address())
        }, (_, _) => ValueTask.FromResult(SecretOutcome<IRuntimeIntegrationClient>.Success(client)),
            RuntimeStalePolicy.FailClosed, TimeSpan.FromMinutes(1), fixture.Time);

    [Test]
    public async Task ConcurrentFinalLeaseReleasesAwaitExactlyOneAsyncRetirement()
    {
        var entered = RuntimeFixture.Signal();
        var release = RuntimeFixture.Signal();
        var fixture = new RuntimeFixture { Value = "prepared" };
        var client = new DualDisposalClient
        {
            Cleanup = async () => { entered.SetResult(); await release.Task; }
        };
        await using var coordinator = AsyncCoordinator(fixture, client);
        await coordinator.EnableAsync();
        RuntimeGenerationLease first = coordinator.Acquire()!;
        RuntimeGenerationLease second = coordinator.Acquire()!;
        await coordinator.DisableAsync();
        Task drain = Task.WhenAll(Task.Run(async () => await first.DisposeAsync()),
            Task.Run(async () => await second.DisposeAsync()));
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.That(drain.IsCompleted).IsFalse();
            await Assert.That(coordinator.Acquire()).IsNull();
        }
        finally { release.TrySetResult(); }
        await drain.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That(client.AsynchronousDisposals).IsEqualTo(1);
    }

    [Test]
    public async Task FailedRejectedCandidateCleanupCannotReturnSuccessfulPreparation()
    {
        var fixture = new RuntimeFixture { Value = "prepared" };
        var client = new DualDisposalClient
        {
            Cleanup = () => throw new InvalidOperationException("synthetic-rejected-cleanup-canary")
        };
        var coordinator = AsyncCoordinator(fixture, client);
        try
        {
            RuntimeActivationObservation result = await coordinator.CheckAgainAsync();
            await Assert.That(result.LastStatus).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(result.Active).IsFalse();
        }
        finally
        {
            await Assert.That(async () => await coordinator.DisposeAsync()).Throws<InvalidOperationException>();
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RepeatedLeaseDisposalRetainsTheSamePendingCompletionAndFailure(bool fails)
    {
        var entered = RuntimeFixture.Signal();
        var release = RuntimeFixture.Signal();
        var fixture = new RuntimeFixture { Value = "prepared" };
        var client = new DualDisposalClient
        {
            Cleanup = async () =>
            {
                entered.SetResult();
                await release.Task;
                if (fails) throw new InvalidOperationException("synthetic-repeated-disposal-canary");
            }
        };
        var coordinator = AsyncCoordinator(fixture, client);
        await coordinator.EnableAsync();
        RuntimeGenerationLease lease = coordinator.Acquire()!;
        await coordinator.DisableAsync();
        Task first = lease.DisposeAsync().AsTask();
        Task? repeated = null;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            repeated = lease.DisposeAsync().AsTask();
            await Assert.That(repeated.IsCompleted).IsFalse();
        }
        finally
        {
            release.TrySetResult();
            foreach (Task disposal in repeated is null ? [first] : new[] { first, repeated })
            {
                if (fails)
                    await Assert.That(async () => await disposal.WaitAsync(TimeSpan.FromSeconds(5)))
                        .Throws<InvalidOperationException>();
                else await disposal.WaitAsync(TimeSpan.FromSeconds(5));
            }
            if (fails)
                await Assert.That(async () => await coordinator.DisposeAsync()).Throws<InvalidOperationException>();
            else await coordinator.DisposeAsync();
        }
        await Assert.That(client.AsynchronousDisposals).IsEqualTo(1);
    }

    [Test]
    public async Task FreshCapabilityCheckCannotReplaceAnAlreadyActiveClient()
    {
        var fixture = new RuntimeFixture { Value = "test-active" };
        await using var coordinator = fixture.Create();
        RuntimeActivationObservation active = await coordinator.EnableAsync();
        fixture.Value = "test-checked";

        RuntimeActivationObservation checkedAgain = await coordinator.CheckAgainAsync();

        await using RuntimeGenerationLease lease = coordinator.Acquire()!;
        await Assert.That(await lease.ExecuteAsync()).IsEqualTo("test-active");
        await Assert.That(checkedAgain.ObservedRevision).IsEqualTo(active.ObservedRevision);
        await Assert.That(fixture.Clients.Single(client => client.Identity == "test-checked").Disposed).IsTrue();
    }

    [Test]
    public async Task FreshCheckAfterFailedEnableCannotActivateDesiredFeature()
    {
        var fixture = new RuntimeFixture();
        await using var coordinator = fixture.Create();
        await coordinator.EnableAsync();
        fixture.Value = "test-now-readable";

        RuntimeActivationObservation checkedAgain = await coordinator.CheckAgainAsync();

        await Assert.That(checkedAgain.DesiredEnabled).IsTrue();
        await Assert.That(checkedAgain.LastStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(checkedAgain.Active).IsFalse();
        await Assert.That(coordinator.Acquire()).IsNull();
        await Assert.That(fixture.Clients.Single().Disposed).IsTrue();
    }

    [Test]
    public async Task FreshCheckSupersedesBlockedEnableWithoutActivatingEitherCandidate()
    {
        var entered = RuntimeFixture.Signal();
        var release = RuntimeFixture.Signal();
        var fixture = new RuntimeFixture { Value = "test-old-candidate" };
        fixture.BeforeValidation = async token =>
        {
            entered.SetResult();
            await release.Task.WaitAsync(token);
        };
        await using var coordinator = fixture.Create();
        Task<RuntimeActivationObservation> enable = coordinator.EnableAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        fixture.BeforeValidation = null;
        fixture.Value = "test-check-candidate";

        RuntimeActivationObservation checkedAgain = await coordinator.CheckAgainAsync();
        release.SetResult();
        await enable.WaitAsync(TimeSpan.FromSeconds(10));

        await Assert.That(checkedAgain.LastStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(coordinator.Acquire()).IsNull();
        await Assert.That(fixture.Clients.Count).IsEqualTo(2);
        await Assert.That(fixture.Clients.All(client => client.Disposed)).IsTrue();
    }

    [Test]
    public async Task AbsentThenSavedThenEnableUsesSameCoordinatorAndRuntimeIdentity()
    {
        var fixture = new RuntimeFixture();
        await using var coordinator = fixture.Create();
        RuntimeActivationObservation absent = await coordinator.EnableAsync();
        await Assert.That(absent.LastStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(coordinator.Acquire()).IsNull();
        fixture.Value = "new-test-credential";
        await Assert.That(coordinator.Observe().Active).IsFalse();
        RuntimeActivationObservation enabled = await coordinator.EnableAsync();
        await using RuntimeGenerationLease lease = coordinator.Acquire()!;
        await Assert.That(await lease.ExecuteAsync()).IsEqualTo(fixture.Value);
        await Assert.That(fixture.ValidatedWithIntendedAuthority).IsTrue();
        await Assert.That(enabled.ObservedRevision).IsEqualTo(enabled.DesiredRevision);
    }

    [Test]
    public async Task CheckAgainCollectsButDoesNotEnableDisabledFeature()
    {
        var fixture = new RuntimeFixture { Value = "test-first" };
        await using var coordinator = fixture.Create();
        RuntimeActivationObservation prepared = await coordinator.CheckAgainAsync();
        await Assert.That(prepared.LastStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(prepared.Active).IsFalse();
        await Assert.That(fixture.Clients.Single().Disposed).IsTrue();
        fixture.Value = "test-second";
        await coordinator.EnableAsync();
        await using RuntimeGenerationLease lease = coordinator.Acquire()!;
        await Assert.That(await lease.ExecuteAsync()).IsEqualTo("test-second");
    }

    [Test]
    public async Task DisableWhileReaderIsBlockedPreventsLateActivation()
    {
        var entered = RuntimeFixture.Signal();
        var release = RuntimeFixture.Signal();
        var fixture = new RuntimeFixture { Value = "test-candidate" };
        fixture.Reader.BeforeRead = async token =>
        {
            entered.TrySetResult();
            await release.Task.WaitAsync(token);
        };
        await using var coordinator = fixture.Create();
        Task<RuntimeActivationObservation> refresh = coordinator.EnableAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        RuntimeActivationObservation disabled = await coordinator.DisableAsync();
        release.SetResult();
        RuntimeActivationObservation late = await refresh.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(late.DesiredRevision).IsEqualTo(disabled.DesiredRevision);
        await Assert.That(late.Active).IsFalse();
        await Assert.That(fixture.Clients.Single().Disposed).IsTrue();
    }

    [Test]
    public async Task DisableDuringApplicationValidationDisposesRejectedCandidate()
    {
        var entered = RuntimeFixture.Signal();
        var release = RuntimeFixture.Signal();
        var fixture = new RuntimeFixture { Value = "test-candidate" };
        fixture.BeforeValidation = async token =>
        {
            entered.SetResult();
            await release.Task.WaitAsync(token);
        };
        await using var coordinator = fixture.Create();
        Task<RuntimeActivationObservation> enable = coordinator.EnableAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await coordinator.DisableAsync();
        release.SetResult();
        await enable.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(coordinator.Acquire()).IsNull();
        await Assert.That(fixture.Clients.Single().Disposed).IsTrue();
    }

    [Test]
    public async Task NewerRefreshWinsEvenWhenOlderValidatorCompletesLast()
    {
        var entered = RuntimeFixture.Signal();
        var release = RuntimeFixture.Signal();
        var fixture = new RuntimeFixture { Value = "test-old" };
        fixture.BeforeValidation = async token =>
        {
            entered.SetResult();
            await release.Task.WaitAsync(token);
        };
        await using var coordinator = fixture.Create();
        Task<RuntimeActivationObservation> old = coordinator.EnableAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        fixture.BeforeValidation = null;
        fixture.Value = "test-new";
        await coordinator.EnableAsync();
        release.SetResult();
        await old.WaitAsync(TimeSpan.FromSeconds(10));
        await using RuntimeGenerationLease lease = coordinator.Acquire()!;
        await Assert.That(await lease.ExecuteAsync()).IsEqualTo("test-new");
        await Assert.That(fixture.Clients.Single(client => client.Identity == "test-old").Disposed).IsTrue();
    }

    [Test]
    public async Task HandoverAndLeaseDisposalKeepExecutingClientAliveUntilCompletion()
    {
        var fixture = new RuntimeFixture { Value = "test-old" };
        await using var coordinator = fixture.Create();
        await coordinator.EnableAsync();
        RuntimeFixture.Client old = fixture.Clients.Single();
        var entered = RuntimeFixture.Signal();
        var release = RuntimeFixture.Signal();
        old.Work = async token =>
        {
            entered.SetResult();
            await release.Task.WaitAsync(token);
        };
        RuntimeGenerationLease lease = coordinator.Acquire()!;
        Task<string> operation = lease.ExecuteAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        fixture.Value = "test-new";
        await coordinator.EnableAsync();
        await lease.DisposeAsync();
        await Assert.That(old.Disposed).IsFalse();
        await using RuntimeGenerationLease next = coordinator.Acquire()!;
        await Assert.That(lease.Revision).IsEqualTo(1L);
        await Assert.That(next.Revision).IsEqualTo(2L);
        await Assert.That(await next.ExecuteAsync()).IsEqualTo("test-new");
        release.SetResult();
        await Assert.That(await operation.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo("test-old");
        await Assert.That(old.Disposed).IsTrue();
        await coordinator.DisableAsync();
        await Assert.That(fixture.Clients.Last().Disposed).IsFalse();
        await next.DisposeAsync();
        await Assert.That(fixture.Clients.Last().Disposed).IsTrue();
    }

    [Test]
    [Arguments(SecretStatus.Pending)]
    [Arguments(SecretStatus.Denied)]
    [Arguments(SecretStatus.Unavailable)]
    [Arguments(SecretStatus.Unknown)]
    public async Task ReadOutcomesRemainDistinctAndDoNotConstructClients(SecretStatus status)
    {
        var fixture = new RuntimeFixture { Failure = status };
        await using var coordinator = fixture.Create();
        await Assert.That((await coordinator.EnableAsync()).LastStatus).IsEqualTo(status);
        await Assert.That(fixture.Clients.Count).IsEqualTo(0);
        await Assert.That(coordinator.Acquire()).IsNull();
    }

    [Test]
    public async Task AppValidatorOwnsAcceptanceAndCanRejectReadableCredential()
    {
        var fixture = new RuntimeFixture { Value = "test-rejected", ValidationFailure = SecretStatus.Invalid };
        await using var coordinator = fixture.Create();
        await Assert.That((await coordinator.EnableAsync()).LastStatus).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(coordinator.Acquire()).IsNull();
    }

    [Test]
    public async Task IndependentReplicaAcknowledgementsDoNotImplyFleetConvergence()
    {
        var first = new RuntimeFixture { Value = "test-first" };
        var second = new RuntimeFixture();
        await using var one = first.Create();
        await using var two = second.Create();
        var replicaOne = new ReplicaRevisionScenario("one", one);
        var replicaTwo = new ReplicaRevisionScenario("two", two);
        var desired = new RuntimeDesiredRevision(7, true);
        RuntimeReplicaAcknowledgement ackOne = await replicaOne.ApplyAsync(desired);
        RuntimeReplicaAcknowledgement ackTwo = await replicaTwo.ApplyAsync(desired);
        await Assert.That(ackOne.ObservedRevision).IsEqualTo(7L);
        await Assert.That(ackTwo.DesiredRevision).IsEqualTo(7L);
        await Assert.That(ackTwo.ObservedRevision).IsEqualTo(0L);
        second.Value = "test-second";
        RuntimeReplicaAcknowledgement recovered = await replicaTwo.ApplyAsync(desired);
        await Assert.That(recovered.ObservedRevision).IsEqualTo(7L);
        await replicaOne.ApplyAsync(new(8, false));
        RuntimeReplicaAcknowledgement obsolete = await replicaOne.ApplyAsync(desired);
        await Assert.That(obsolete.ObservedRevision).IsEqualTo(8L);
        await Assert.That(obsolete.Active).IsFalse();
    }

    [Test]
    public async Task ReplicaDisableDoesNotWaitForOlderBlockedEnable()
    {
        var entered = RuntimeFixture.Signal();
        var release = RuntimeFixture.Signal();
        var fixture = new RuntimeFixture { Value = "test-candidate" };
        fixture.BeforeValidation = async token =>
        {
            entered.SetResult();
            await release.Task.WaitAsync(token);
        };
        await using var coordinator = fixture.Create();
        var replica = new ReplicaRevisionScenario("one", coordinator);
        Task<RuntimeReplicaAcknowledgement> enabling = replica.ApplyAsync(new(1, true)).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        RuntimeReplicaAcknowledgement disabled = await replica.ApplyAsync(new(2, false));
        await Assert.That(disabled.ObservedRevision).IsEqualTo(2L);
        release.SetResult();
        RuntimeReplicaAcknowledgement late = await enabling.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(late.Active).IsFalse();
        await Assert.That(late.ObservedRevision).IsEqualTo(2L);
        await Assert.That(fixture.Clients.Single().Disposed).IsTrue();
    }

    [Test]
    public async Task IncompleteRequiredMappingNeverReachesApplicationValidator()
    {
        var fixture = new RuntimeFixture { Value = "test-one-key" };
        var second = new SecretReference(fixture.Reader.Authority, new RuntimeFixture.Address());
        fixture.Reader.AbsentReference = second;
        bool validated = false;
        await using var coordinator = new RuntimeIntegrationCoordinator(fixture.Reader,
            new Dictionary<string, SecretReference>
            {
                ["first"] = new(fixture.Reader.Authority, new RuntimeFixture.Address()),
                ["second"] = second
            }, (_, _) =>
            {
                validated = true;
                return ValueTask.FromResult(SecretOutcome<IRuntimeIntegrationClient>.Success(
                    new RuntimeFixture.Client("invalid-partial")));
            }, RuntimeStalePolicy.FailClosed, TimeSpan.FromMinutes(1), fixture.Time);
        await Assert.That((await coordinator.EnableAsync()).LastStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(validated).IsFalse();
        await Assert.That(coordinator.Acquire()).IsNull();
    }

    [Test]
    public async Task CancellationAfterCandidateConstructionDisposesClientAndPropagates()
    {
        var fixture = new RuntimeFixture { Value = "test-cancelled" };
        using var cancellation = new CancellationTokenSource();
        var client = new RuntimeFixture.Client("test-cancelled");
        await using var coordinator = new RuntimeIntegrationCoordinator(fixture.Reader,
            new Dictionary<string, SecretReference>
            {
                ["credential"] = new(fixture.Reader.Authority, new RuntimeFixture.Address())
            }, (_, _) =>
            {
                cancellation.Cancel();
                return ValueTask.FromResult(SecretOutcome<IRuntimeIntegrationClient>.Success(client));
            }, RuntimeStalePolicy.FailClosed, TimeSpan.FromMinutes(1), fixture.Time);
        await Assert.That(async () => await coordinator.EnableAsync(cancellation.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(client.Disposed).IsTrue();
        await Assert.That(coordinator.Observe().LastStatus).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(coordinator.Acquire()).IsNull();
    }
}

internal sealed class RuntimeFixture
{
    internal sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
    internal sealed class Address : SecretAddress;
    internal sealed class ControlledReader(RuntimeFixture owner) : ISecretReader
    {
        public SecretAuthority Authority { get; } = new();
        internal Func<CancellationToken, Task>? BeforeRead;
        internal SecretReference? AbsentReference;
        public async ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference,
            CancellationToken cancellationToken = default)
        {
            if (BeforeRead is { } barrier) await barrier(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            if (ReferenceEquals(reference, AbsentReference))
                return SecretOutcome<SecretRead>.Failure(SecretStatus.Absent);
            if (owner.Failure is { } failure) return SecretOutcome<SecretRead>.Failure(failure);
            if (owner.Value is null) return SecretOutcome<SecretRead>.Failure(SecretStatus.Absent);
            return SecretOutcome<SecretRead>.Success(new(SecretMaterial.FromText(owner.Value),
                new(reference, null, owner.Time.Now, SecretValidity.Valid, owner.Expiry)));
        }
    }
    internal sealed class Client(string identity) : IRuntimeIntegrationClient
    {
        internal string Identity { get; } = identity;
        internal bool Disposed;
        internal Func<CancellationToken, Task>? Work;
        public async ValueTask<string> ExecuteAsync(CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Disposed, this);
            if (Work is { } work) await work(cancellationToken);
            ObjectDisposedException.ThrowIf(Disposed, this);
            return Identity;
        }
        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }
    internal RuntimeFixture() => Reader = new(this);
    internal Clock Time { get; } = new();
    internal ControlledReader Reader { get; }
    internal string? Value;
    internal SecretStatus? Failure;
    internal SecretStatus? ValidationFailure;
    internal DateTimeOffset? Expiry;
    internal bool ValidatedWithIntendedAuthority;
    internal Func<CancellationToken, Task>? BeforeValidation;
    internal List<Client> Clients { get; } = [];
    internal static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal RuntimeIntegrationCoordinator Create(RuntimeStalePolicy policy = RuntimeStalePolicy.FailClosed) =>
        new(Reader, new Dictionary<string, SecretReference>
        {
            ["credential"] = new(Reader.Authority, new Address())
        }, Validate, policy, TimeSpan.FromMinutes(5), Time);

    private async ValueTask<SecretOutcome<IRuntimeIntegrationClient>> Validate(SecretSnapshotHandle candidate,
        CancellationToken cancellationToken)
    {
        using SecretRead read = candidate.Read("credential");
        ValidatedWithIntendedAuthority = read.Observation.Reference.BelongsTo(Reader.Authority);
        string identity = read.Material.Reveal();
        if (BeforeValidation is { } barrier) await barrier(cancellationToken);
        if (ValidationFailure is { } failure) return SecretOutcome<IRuntimeIntegrationClient>.Failure(failure);
        var client = new Client(identity);
        Clients.Add(client);
        return SecretOutcome<IRuntimeIntegrationClient>.Success(client);
    }
}
