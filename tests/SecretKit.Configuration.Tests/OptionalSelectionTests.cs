using Microsoft.Extensions.Configuration;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;

namespace SecretKit.Configuration.Tests;

public sealed class OptionalSelectionTests
{
    [Test]
    public async Task AbsenceOnlyGenerationMasksLowerConfigurationAndCanReappear()
    {
        var reader = new SelectionReader { Status = SecretStatus.Absent };
        using var loader = new SecretSnapshotLoader([reader.Select("optional", SecretPresencePolicy.Optional)]);
        await Assert.That((await loader.RefreshAsync()).IsSuccess).IsTrue();
        using var absent = loader.Acquire();
        await Assert.That(absent.Count).IsEqualTo(0);
        await Assert.That(absent.SelectionCount).IsEqualTo(1);
        await Assert.That(absent.ReadOutcome("optional").Status).IsEqualTo(SecretStatus.Absent);
        await Assert.That(() => absent.Read("optional")).Throws<InvalidOperationException>();
        await Assert.That(() => absent.ReadOutcome("unknown")).Throws<ArgumentException>();
        using var export = SecretConfigurationExport.Create(
            absent, [new("optional", "Service:Value")]);
        IConfigurationRoot root = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["Service:Value"] = "must-not-resurrect" }).Add(export).Build();
        using var lifetime = (IDisposable)root;
        await Assert.That(root["Service:Value"]).IsNull();
        await Assert.That(root.Providers.Last().TryGet("Service:Value", out string? value)).IsTrue();
        await Assert.That(value).IsNull();

        reader.Status = SecretStatus.Success;
        await loader.RefreshAsync();
        using var present = loader.Acquire();
        using SecretRead copy = present.ReadOutcome("optional").Value;
        await Assert.That(present.Count).IsEqualTo(1);
        await Assert.That(copy.Material.Reveal()).IsEqualTo(reader.Text);
        reader.Status = SecretStatus.Absent;
        await loader.RefreshAsync();
        using var disappeared = loader.Acquire();
        await Assert.That(disappeared.Count).IsEqualTo(0);
        await Assert.That(copy.Material.Reveal()).IsEqualTo(reader.Text);
        await Assert.That(reader.Reads).IsEqualTo(3);
        absent.Dispose();
        await Assert.That(() => absent.ReadOutcome("optional")).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments(SecretStatus.Denied)]
    [Arguments(SecretStatus.Unavailable)]
    [Arguments(SecretStatus.Invalid)]
    [Arguments(SecretStatus.Expired)]
    public async Task OptionalDoesNotConvertFailuresToAbsence(SecretStatus status)
    {
        var reader = new SelectionReader();
        using var loader = new SecretSnapshotLoader([reader.Select("value", SecretPresencePolicy.Optional)]);
        await loader.RefreshAsync();
        using var old = loader.Acquire();
        reader.Status = status;
        reader.Reason = SecretFailureReason.InvalidResponse;
        reader.RetryAfter = status == SecretStatus.Unavailable ? TimeSpan.FromSeconds(3) : null;
        SecretOutcome<long> failure = await loader.RefreshAsync();
        await Assert.That(failure.Status).IsEqualTo(status);
        await Assert.That(failure.Reason).IsEqualTo(reader.Reason);
        await Assert.That(failure.RetryAfter).IsEqualTo(reader.RetryAfter);
        await Assert.That(loader.LastAttempt!.Reason).IsEqualTo(reader.Reason);
        await Assert.That(loader.LastAttempt!.RetryAfter).IsEqualTo(reader.RetryAfter);
        using var current = loader.Acquire();
        await Assert.That(current.Generation).IsEqualTo(old.Generation);
    }

    [Test]
    [Arguments(SecretValidity.Expired, SecretStatus.Expired)]
    [Arguments(SecretValidity.Unknown, SecretStatus.Invalid)]
    [Arguments(SecretValidity.Disabled, SecretStatus.Invalid)]
    public async Task OptionalStillRequiresValidDeliveredMaterial(SecretValidity validity, SecretStatus status)
    {
        var reader = new SelectionReader { Validity = validity };
        using var loader = new SecretSnapshotLoader([reader.Select("value", SecretPresencePolicy.Optional)]);
        await Assert.That((await loader.RefreshAsync()).Status).IsEqualTo(status);
        await Assert.That(() => reader.Delivered.Single().Material.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(() => loader.Acquire()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task PresencePolicyAndDuplicatesFailBeforeAnyRead()
    {
        var reader = new SelectionReader();
        await Assert.That(() => reader.Select("value", (SecretPresencePolicy)42)).Throws<ArgumentOutOfRangeException>();
        SecretSelection selection = reader.Select("value", SecretPresencePolicy.Optional);
        await Assert.That(() => new SecretSnapshotLoader([selection, selection])).Throws<ArgumentException>();
        await Assert.That(reader.Reads).IsEqualTo(0);
        using var required = new SecretSnapshotLoader([reader.Select("value")]);
        reader.Status = SecretStatus.Absent;
        await Assert.That((await required.RefreshAsync()).Status).IsEqualTo(SecretStatus.Absent);
        await Assert.That(() => required.Acquire()).Throws<InvalidOperationException>();
    }
}

internal sealed class SelectionAddress : SecretAddress;

internal sealed class SelectionReader : ISecretReader, IDisposable
{
    public SecretAuthority Authority { get; } = new();
    public SecretStatus Status { get; set; } = SecretStatus.Success;
    public SecretFailureReason Reason { get; set; }
    public TimeSpan? RetryAfter { get; set; }
    public SecretValidity Validity { get; set; } = SecretValidity.Valid;
    public string Text { get; set; } = "synthetic-value";
    public DateTimeOffset? Expiry { get; set; }
    public SecretReference? ForeignReference { get; set; }
    public bool DisposeBeforeDelivery { get; set; }
    public bool Disposed { get; private set; }
    public int Reads { get; private set; }
    public List<SecretRead> Delivered { get; } = [];
    public Task<SecretOutcome<SecretRead>>? LastOperation { get; private set; }
    public Func<CancellationToken, Task>? BeforeRead { get; set; }
    public SecretSelection Select(string key, SecretPresencePolicy presence = SecretPresencePolicy.Required) =>
        new(key, this, new SecretReference(Authority, new SelectionAddress()), presence);

    public ValueTask<SecretOutcome<SecretRead>> ReadAsync(
        SecretReference reference, CancellationToken cancellationToken = default)
    {
        Reads++;
        LastOperation = ReadCoreAsync(reference, cancellationToken);
        return new ValueTask<SecretOutcome<SecretRead>>(LastOperation);
    }

    private async Task<SecretOutcome<SecretRead>> ReadCoreAsync(
        SecretReference reference, CancellationToken cancellationToken)
    {
        if (BeforeRead is not null) await BeforeRead(cancellationToken);
        if (Status != SecretStatus.Success)
            return SecretOutcome<SecretRead>.Failure(Status, RetryAfter, Reason);
        var read = new SecretRead(SecretMaterial.FromText(Text),
            new SecretObservation(ForeignReference ?? reference, null, DateTimeOffset.UnixEpoch, Validity, Expiry));
        Delivered.Add(read);
        if (DisposeBeforeDelivery) read.Dispose();
        return SecretOutcome<SecretRead>.Success(read);
    }

    public void Dispose() => Disposed = true;
}
