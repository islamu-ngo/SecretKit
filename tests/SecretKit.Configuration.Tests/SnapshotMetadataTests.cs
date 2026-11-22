using SecretKit.Core;
using SecretKit.Extensions.Configuration;

namespace SecretKit.Configuration.Tests;

[NotInParallel]
public sealed class SnapshotMetadataTests
{
    [Test]
    public async Task ExpiryInspectionDoesNotAllocateAnotherMaterialPayload()
    {
        using var seed = SecretMaterial.FromText(new string('s', 2 * 1024 * 1024));
        var reader = new Reader(seed);
        var reference = new SecretReference(reader.Authority, new Address());
        await using var coordinator = new SecretGenerationCoordinator<Client>(reader,
            new Dictionary<string, SecretReference> { ["key"] = reference },
            static (_, _) => ValueTask.FromResult(SecretOutcome<Client>.Success(new Client())),
            SecretGenerationStalePolicy.FailClosed, TimeSpan.FromHours(1), TimeProvider.System);
        await coordinator.EnableAsync();

        long before = GC.GetTotalAllocatedBytes(precise: true);
        SecretGenerationObservation observation = await coordinator.EnableAsync();
        long allocated = GC.GetTotalAllocatedBytes(precise: true) - before;

        await Assert.That(observation.Active).IsTrue();
        // The reader and loader each own one payload copy. Metadata inspection
        // must not allocate a third. The fixed allowance covers framework and
        // observation objects, independently of the two-megabyte payload.
        await Assert.That(allocated).IsLessThan(2L * seed.GetUtf8ByteCount() + 256 * 1024);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task MetadataPreservesPresenceAndHandleLifetimeWithoutAllocations(bool absent)
    {
        using var seed = SecretMaterial.FromText("metadata-only-canary");
        var reader = new Reader(seed) { Absent = absent };
        var reference = new SecretReference(reader.Authority, new Address());
        using var loader = new SecretSnapshotLoader(
            [new SecretSelection("key", reader, reference, SecretPresencePolicy.Optional)]);
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        bool present = handle.TryGetObservation("key", out SecretObservation? metadata);
        await Assert.That(present).IsEqualTo(!absent);
        await Assert.That(metadata?.Reference).IsEqualTo(absent ? null : reference);
        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int index = 0; index < 100; index++) handle.TryGetObservation("key", out _);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        await Assert.That(allocated).IsEqualTo(0);
        await Assert.That(() => handle.TryGetObservation("undeclared", out _)).Throws<ArgumentException>();
        handle.Dispose();
        await Assert.That(() => handle.TryGetObservation("key", out _)).Throws<ObjectDisposedException>();
    }

    private sealed class Address : SecretAddress;
    private sealed class Client : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class Reader(SecretMaterial seed) : ISecretReader
    {
        public bool Absent { get; init; }
        public SecretAuthority Authority { get; } = new();
        public ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Absent) return ValueTask.FromResult(SecretOutcome<SecretRead>.Failure(SecretStatus.Absent));
            return ValueTask.FromResult(SecretOutcome<SecretRead>.Success(new(seed.Copy(),
                new SecretObservation(reference, null, DateTimeOffset.UtcNow, SecretValidity.Valid))));
        }
    }
}
