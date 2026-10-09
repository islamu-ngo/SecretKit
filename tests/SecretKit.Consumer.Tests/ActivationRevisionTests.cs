using SecretKit.Core;
using SecretKit.Extensions.Configuration;
using SecretKit.Samples.RuntimeConfiguration;

namespace SecretKit.Consumer.Tests;

public sealed class ActivationRevisionTests
{
    [Test]
    public async Task AbsentThenSavedThenEnableUsesSameCoordinatorAndRuntimeIdentity()
    {
        var fixture = new RuntimeFixture();
        using var coordinator = fixture.Create();
        RuntimeActivationObservation absent = await coordinator.EnableAsync();
        await Assert.That(absent.LastStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(coordinator.Acquire()).IsNull();
        fixture.Value = "new-test-credential";
        await Assert.That(coordinator.Observe().Active).IsFalse();
        RuntimeActivationObservation enabled = await coordinator.EnableAsync();
        using RuntimeGenerationLease lease = coordinator.Acquire()!;
        await Assert.That(await lease.ExecuteAsync()).IsEqualTo(fixture.Value);
        await Assert.That(fixture.ValidatedWithIntendedAuthority).IsTrue();
        await Assert.That(enabled.ObservedRevision).IsEqualTo(enabled.DesiredRevision);
    }

    [Test]
    public async Task CheckAgainCollectsButDoesNotEnableDisabledFeature()
    {
        var fixture = new RuntimeFixture { Value = "test-first" };
        using var coordinator = fixture.Create();
        RuntimeActivationObservation prepared = await coordinator.CheckAgainAsync();
        await Assert.That(prepared.LastStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(prepared.Active).IsFalse();
        await Assert.That(fixture.Clients.Single().Disposed).IsTrue();
        fixture.Value = "test-second";
        await coordinator.EnableAsync();
        using RuntimeGenerationLease lease = coordinator.Acquire()!;
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
        using var coordinator = fixture.Create();
        Task<RuntimeActivationObservation> refresh = coordinator.EnableAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        RuntimeActivationObservation disabled = coordinator.Disable();
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
        using var coordinator = fixture.Create();
        Task<RuntimeActivationObservation> enable = coordinator.EnableAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        coordinator.Disable();
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
        using var coordinator = fixture.Create();
        Task<RuntimeActivationObservation> old = coordinator.EnableAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        fixture.BeforeValidation = null;
        fixture.Value = "test-new";
        await coordinator.CheckAgainAsync();
        release.SetResult();
        await old.WaitAsync(TimeSpan.FromSeconds(10));
        using RuntimeGenerationLease lease = coordinator.Acquire()!;
        await Assert.That(await lease.ExecuteAsync()).IsEqualTo("test-new");
        await Assert.That(fixture.Clients.Single(client => client.Identity == "test-old").Disposed).IsTrue();
    }

    [Test]
    public async Task HandoverAndLeaseDisposalKeepExecutingClientAliveUntilCompletion()
    {
        var fixture = new RuntimeFixture { Value = "test-old" };
        using var coordinator = fixture.Create();
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
        await coordinator.CheckAgainAsync();
        lease.Dispose();
        await Assert.That(old.Disposed).IsFalse();
        using RuntimeGenerationLease next = coordinator.Acquire()!;
        await Assert.That(await next.ExecuteAsync()).IsEqualTo("test-new");
        release.SetResult();
        await Assert.That(await operation.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo("test-old");
        await Assert.That(old.Disposed).IsTrue();
        coordinator.Disable();
        await Assert.That(fixture.Clients.Last().Disposed).IsFalse();
        next.Dispose();
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
        using var coordinator = fixture.Create();
        await Assert.That((await coordinator.EnableAsync()).LastStatus).IsEqualTo(status);
        await Assert.That(fixture.Clients.Count).IsEqualTo(0);
        await Assert.That(coordinator.Acquire()).IsNull();
    }

    [Test]
    public async Task AppValidatorOwnsAcceptanceAndCanRejectReadableCredential()
    {
        var fixture = new RuntimeFixture { Value = "test-rejected", ValidationFailure = SecretStatus.Invalid };
        using var coordinator = fixture.Create();
        await Assert.That((await coordinator.EnableAsync()).LastStatus).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(coordinator.Acquire()).IsNull();
    }

    [Test]
    public async Task IndependentReplicaAcknowledgementsDoNotImplyFleetConvergence()
    {
        var first = new RuntimeFixture { Value = "test-first" };
        var second = new RuntimeFixture();
        using var one = first.Create();
        using var two = second.Create();
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
        using var coordinator = fixture.Create();
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
        using var coordinator = new RuntimeIntegrationCoordinator(fixture.Reader,
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
        using var coordinator = new RuntimeIntegrationCoordinator(fixture.Reader,
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
        public void Dispose() => Disposed = true;
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
