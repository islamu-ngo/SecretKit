using System.Security.Cryptography;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;
using SecretKit.Samples.RuntimeConfiguration;

namespace SecretKit.Consumer.Tests;

public sealed class ConsumerGenerationTests
{
    [Test]
    public async Task SerialCompositionWorkloadReadsOnlySelectedRequiredAndOptionalGroups()
    {
        CompositionMeasurement measured = await BootstrapScenario.RunCompositionAsync();

        await Assert.That(measured.SelectedReads).IsEqualTo(7);
    }

    [Test]
    public async Task LogicalDatabaseOperationKeepsOneGenerationDuringRefresh()
    {
        string old = Material();
        string next = Material();
        string current = old;
        var reader = new Reader(reference => Success(reference, current));
        using var loader = new SecretSnapshotLoader([
            new SecretSelection("username", reader, new SecretReference(reader.Authority, new Address())),
            new SecretSelection("password", reader, new SecretReference(reader.Authority, new Address()))
        ]);
        await loader.RefreshAsync();
        using SecretSnapshotHandle operation = loader.Acquire();
        using SecretRead first = operation.Read("username");

        current = next;
        await loader.RefreshAsync();

        using SecretRead second = operation.Read("password");
        using SecretSnapshotHandle newOperation = loader.Acquire();
        using SecretRead newFirst = newOperation.Read("username");
        using SecretRead newSecond = newOperation.Read("password");
        await Assert.That(first.Material.Reveal()).IsEqualTo(old);
        await Assert.That(second.Material.Reveal()).IsEqualTo(old);
        await Assert.That(newFirst.Material.Reveal()).IsEqualTo(next);
        await Assert.That(newSecond.Material.Reveal()).IsEqualTo(next);
        await Assert.That(operation.RemoteSnapshotGuaranteed).IsFalse();
        await Assert.That(newOperation.Generation > operation.Generation).IsTrue();
    }

    [Test]
    public async Task CheckAgainReadsNewProviderValueWithoutProcessRestartOrCachedAbsence()
    {
        string? current = null;
        var reader = new Reader(reference => current is null
            ? SecretOutcome<SecretRead>.Failure(SecretStatus.Absent) : Success(reference, current));
        using var loader = new SecretSnapshotLoader([
            new SecretSelection("optional-integration", reader, new SecretReference(reader.Authority, new Address()))
        ]);
        SecretOutcome<long> absent = await loader.RefreshAsync();
        await Assert.That(absent.Status).IsEqualTo(SecretStatus.Absent);
        await Assert.That(() => loader.Acquire()).Throws<InvalidOperationException>();

        current = Material();
        SecretOutcome<long> checkedAgain = await loader.RefreshAsync();

        await Assert.That(checkedAgain.IsSuccess).IsTrue();
        using SecretSnapshotHandle candidate = loader.Acquire();
        using SecretRead fresh = candidate.Read("optional-integration");
        await Assert.That(fresh.Material.Reveal()).IsEqualTo(current);
        // Preparing a credential candidate alone does not activate a client or send business traffic.
    }

    private static string Material() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private static SecretOutcome<SecretRead> Success(SecretReference reference, string material) =>
        SecretOutcome<SecretRead>.Success(new SecretRead(SecretMaterial.FromText(material),
            new SecretObservation(reference, null, DateTimeOffset.UtcNow, SecretValidity.Valid)));
    private sealed class Address : SecretAddress;
    private sealed class Reader(Func<SecretReference, SecretOutcome<SecretRead>> read) : ISecretReader
    {
        public SecretAuthority Authority { get; } = new();
        public ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(read(reference));
        }
    }
}
