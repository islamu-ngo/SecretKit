using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class InfisicalSecretScopeTests
{
    [Test]
    public async Task ScopeBindsCoordinatesAndPreservesOwnedReads()
    {
        var reader = new Reader();
        var scope = reader.CreateScope("canary-project", "canary-env", "/canary-folder");
        using var read = await scope.GetSecretAsync("canary-key");
        var address = (InfisicalSecretAddress)read.Observation.Reference.Address;
        await Assert.That(address.ProjectId).IsEqualTo("canary-project");
        await Assert.That(address.Environment).IsEqualTo("canary-env");
        await Assert.That(address.Folder).IsEqualTo("/canary-folder");
        await Assert.That(address.Key).IsEqualTo("canary-key");
        await Assert.That(read.Observation.Reference.BelongsTo(reader.Authority)).IsTrue();
        await Assert.That(read.Material.Reveal()).IsEqualTo("value-canary");
        await Assert.That(JsonSerializer.Serialize(scope).Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task OnlyAbsenceBecomesNullAndFailureDiagnosticsRemainCoordinateFree()
    {
        var reader = new Reader { Status = SecretStatus.Absent };
        var scope = reader.CreateScope("canary-project", "canary-env");
        await Assert.That(await scope.TryGetSecretAsync("canary-key")).IsNull();
        reader.Status = SecretStatus.Denied;
        try
        {
            using var read = await scope.TryGetSecretAsync("canary-key");
            throw new InvalidOperationException("Denied access returned a value.");
        }
        catch (SecretUnavailableException error)
        {
            await Assert.That(error.Status).IsEqualTo(SecretStatus.Denied);
            await Assert.That(error.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
        }
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.That(async () => await scope.ReadAsync("canary-key", cancellation.Token)).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task IncompleteInventoryNeverEstablishesAbsence()
    {
        var reader = new Reader { Complete = false };
        var scope = reader.CreateScope("canary-project", "canary-env");
        await Assert.That((await scope.InspectAsync("missing")).Status).IsEqualTo(SecretStatus.Unknown);
        reader.Complete = true;
        await Assert.That((await scope.InspectAsync("missing")).Status).IsEqualTo(SecretStatus.Absent);
    }

    [Test]
    public async Task MetadataRetainsTheSelectedAuthorityAndRejectsForeignCoordinates()
    {
        var reader = new Reader();
        var scope = reader.CreateScope("canary-project", "canary-env");
        reader.Items = [new(new(reader.Authority, new InfisicalSecretAddress("canary-project", "canary-env", "/", "key")),
            "7", DateTimeOffset.UnixEpoch, SecretValidity.Unknown)];
        var result = await scope.InspectAsync("key");
        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value.Version).IsEqualTo("7");
        await Assert.That(result.Value.Reference.BelongsTo(reader.Authority)).IsTrue();
        reader.Items = [new(new(reader.Authority, new InfisicalSecretAddress("foreign-project", "canary-env", "/", "key")),
            "8", DateTimeOffset.UnixEpoch, SecretValidity.Unknown)];
        await Assert.That((await scope.InspectAsync("key")).Status).IsEqualTo(SecretStatus.Invalid);
    }

    private sealed class Reader : IInfisicalSecretReader
    {
        public SecretAuthority Authority { get; } = new();
        public SecretStatus Status { get; set; } = SecretStatus.Success;
        public bool Complete { get; set; } = true;
        public SecretObservation[] Items { get; set; } = [];
        public ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Status == SecretStatus.Success
                ? SecretOutcome<SecretRead>.Success(new(SecretMaterial.FromText("value-canary"),
                    new(reference, null, DateTimeOffset.UnixEpoch, SecretValidity.Valid)))
                : SecretOutcome<SecretRead>.Failure(Status));
        }
        public ValueTask<SecretOutcome<SecretInventory>> InspectAsync(SecretInventoryScope scope, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(SecretOutcome<SecretInventory>.Success(new(Items, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, Complete)));
    }
}
