using SecretKit.Core;
using SecretKit.Extensions.Configuration;

namespace SecretKit.Configuration.Tests;

public sealed class GenerationConcurrencyInvariantTests
{
    [Test]
    public async Task CheckAgainCannotSupersedeAnActivationAwaitingValidation()
    {
        var validating = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var checkingValidation = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var active = new Client();
        var checkedClient = new Client();
        int validations = 0;
        await using var coordinator = Create(async (_, _) =>
        {
            if (Interlocked.Increment(ref validations) == 1)
            {
                validating.SetResult();
                await release.Task;
                return SecretOutcome<Client>.Success(active);
            }
            checkingValidation.SetResult();
            return SecretOutcome<Client>.Success(checkedClient);
        });
        Task<SecretGenerationObservation> enabling = coordinator.EnableAsync().AsTask();
        Task<SecretGenerationObservation>? checking = null;
        try
        {
            await validating.Task.WaitAsync(TimeSpan.FromSeconds(5));
            checking = coordinator.CheckAgainAsync().AsTask();
            await checkingValidation.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally { release.TrySetResult(); }
        await enabling.WaitAsync(TimeSpan.FromSeconds(5));
        await checking!.WaitAsync(TimeSpan.FromSeconds(5));

        await using SecretGenerationLease<Client>? lease = coordinator.Acquire();
        await Assert.That(lease).IsNotNull();
        await Assert.That(await lease!.ExecuteAsync((client, _) =>
            ValueTask.FromResult(ReferenceEquals(client, active)))).IsTrue();
        await Assert.That(active.Disposals).IsEqualTo(0);
        await Assert.That(checkedClient.Disposals).IsEqualTo(1);
    }

    [Test]
    public async Task FailedOldRetirementPreservesPublishedHealthyGeneration()
    {
        var old = new Client { FailDisposal = true };
        var healthy = new Client();
        int validations = 0;
        var coordinator = Create((_, _) => ValueTask.FromResult(
            SecretOutcome<Client>.Success(++validations == 1 ? old : healthy)));
        try
        {
            await coordinator.EnableAsync();
            SecretGenerationObservation result = await coordinator.EnableAsync();
            await Assert.That(result.Active).IsTrue();
            await using SecretGenerationLease<Client>? lease = coordinator.Acquire();
            await Assert.That(lease).IsNotNull();
            await Assert.That(await lease!.ExecuteAsync((client, _) =>
                ValueTask.FromResult(ReferenceEquals(client, healthy)))).IsTrue();
            await Assert.That(old.Disposals).IsEqualTo(1);
            await Assert.That(healthy.Disposals).IsEqualTo(0);
        }
        finally
        {
            // The historical cleanup failure remains observable at shutdown.
            await Assert.That(async () => await coordinator.DisposeAsync()).Throws<InvalidOperationException>();
        }
    }

    private static SecretGenerationCoordinator<Client> Create(
        Func<SecretSnapshotHandle, CancellationToken, ValueTask<SecretOutcome<Client>>> validate)
    {
        var reader = new Reader();
        return new(reader, new Dictionary<string, SecretReference>
        { ["key"] = new(reader.Authority, new Address()) },
            validate, SecretGenerationStalePolicy.FailClosed, TimeSpan.FromHours(1), TimeProvider.System);
    }

    private sealed class Client : IAsyncDisposable
    {
        internal bool FailDisposal { get; init; }
        internal int Disposals { get; private set; }
        public ValueTask DisposeAsync()
        {
            Disposals++;
            if (FailDisposal) throw new InvalidOperationException("retirement-canary");
            return ValueTask.CompletedTask;
        }
    }

    private sealed class Address : SecretAddress;
    private sealed class Reader : ISecretReader
    {
        public SecretAuthority Authority { get; } = new();
        public ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference,
            CancellationToken cancellationToken = default) => ValueTask.FromResult(
                SecretOutcome<SecretRead>.Success(new(SecretMaterial.FromText("synthetic"),
                    new SecretObservation(reference, null, DateTimeOffset.UtcNow, SecretValidity.Valid))));
    }
}
