using Microsoft.Extensions.Configuration;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;

namespace SecretKit.Configuration.Tests;

public sealed class PreparedConfigurationTests
{
    [Test]
    public async Task PreparationOwnsMaterialButBorrowsReaderAndExportsOnlyExplicitlyOnce()
    {
        var reader = new SelectionReader { Text = "prepared-canary" };
        var outcome = await PreparedSecretConfiguration.PrepareAsync([reader.Select("value")]);
        await Assert.That(outcome.IsSuccess).IsTrue();
        using var prepared = outcome.Value;
        using SecretRead copy = prepared.Read("value");
        await Assert.That(reader.Reads).IsEqualTo(1);
        IConfigurationRoot root = prepared.ExportAcknowledgingManagedStrings([new("value", "Service:Value")]);
        await Assert.That(root["Service:Value"]).IsEqualTo(reader.Text);
        await Assert.That(reader.Reads).IsEqualTo(1);
        await Assert.That(() => prepared.ExportAcknowledgingManagedStrings([new("value", "Other")]))
            .Throws<InvalidOperationException>();
        prepared.Dispose();
        prepared.Dispose();
        await Assert.That(reader.Disposed).IsFalse();
        await Assert.That(root["Service:Value"]).IsNull();
        await Assert.That(copy.Material.Reveal()).IsEqualTo(reader.Text);
        await Assert.That(() => prepared.ReadOutcome("value")).Throws<ObjectDisposedException>();
        await Assert.That(() => prepared.ExportAcknowledgingManagedStrings([new("value", "Other")]))
            .Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task FailedPreparationPreservesFailureAndClearsPartialMaterial()
    {
        var first = new SelectionReader();
        var failed = new SelectionReader
        {
            Status = SecretStatus.Unavailable,
            Reason = SecretFailureReason.DeadlineExceeded,
            RetryAfter = TimeSpan.FromSeconds(1)
        };
        var result = await PreparedSecretConfiguration.PrepareAsync([first.Select("0"), failed.Select("1")]);
        await Assert.That(result.Status).IsEqualTo(failed.Status);
        await Assert.That(result.Reason).IsEqualTo(failed.Reason);
        await Assert.That(result.RetryAfter).IsEqualTo(failed.RetryAfter);
        await Assert.That(() => first.Delivered.Single().Material.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(first.Disposed || failed.Disposed).IsFalse();
    }

    [Test]
    public async Task MappingValidationPrecedesAnyRevealAndRejectedMappingCanBeCorrected()
    {
        var reader = new SelectionReader();
        using var prepared = (await PreparedSecretConfiguration.PrepareAsync([reader.Select("value")])).Value;
        await Assert.That(() => prepared.ExportAcknowledgingManagedStrings(
            [new("value", "same"), new("value", "SAME")])).Throws<ArgumentException>();
        await Assert.That(() => prepared.ExportAcknowledgingManagedStrings(
            [new("value", "first"), new("unknown", "second")])).Throws<ArgumentException>();
        IConfigurationRoot root = prepared.ExportAcknowledgingManagedStrings([new("value", "Service:Value")]);
        await Assert.That(root["Service:Value"]).IsEqualTo(reader.Text);
        await Assert.That(reader.Reads).IsEqualTo(1);
    }

    [Test]
    public async Task MaterialOnlyPreparationAcceptsAbsenceWithoutBuildingConfiguration()
    {
        var reader = new SelectionReader { Status = SecretStatus.Absent };
        using var prepared = (await PreparedSecretConfiguration.PrepareAsync(
            [reader.Select("optional", SecretPresencePolicy.Optional)])).Value;
        await Assert.That(prepared.ReadOutcome("optional").Status).IsEqualTo(SecretStatus.Absent);
        await Assert.That(() => prepared.Read("optional")).Throws<InvalidOperationException>();
        IConfigurationRoot root = prepared.ExportAcknowledgingManagedStrings([new("optional", "Value")]);
        await Assert.That(root.Providers.Single().TryGet("Value", out string? value)).IsTrue();
        await Assert.That(value).IsNull();
    }
}
