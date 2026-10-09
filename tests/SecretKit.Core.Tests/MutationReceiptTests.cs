using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Core.Tests;

public sealed class MutationReceiptTests
{
    [Test]
    public async Task LocalReceiptCannotBeReassignedOrReplayed()
    {
        var target = new SecretReference(new SecretAuthority(), new Address());
        var other = new SecretReference(new SecretAuthority(), new Address());
        var receipt = new MutationReceipt(target);

        await Assert.That(() => receipt.BeginDispatch(other)).Throws<InvalidOperationException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        receipt.BeginDispatch(target);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(() => receipt.BeginDispatch(target)).Throws<InvalidOperationException>();
        receipt.Record(DispatchEvidence.Applied);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(() => receipt.Record(DispatchEvidence.Rejected)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task UnknownEffectCannotBeResetToNoDispatch()
    {
        var target = new SecretReference(new SecretAuthority(), new Address());
        var receipt = new MutationReceipt(target);
        receipt.BeginDispatch(target);

        await Assert.That(() => receipt.Record(DispatchEvidence.NotDispatched)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(JsonSerializer.Serialize(receipt).Contains("coordinate", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(receipt).Contains(receipt.LocalId.ToString(), StringComparison.Ordinal)).IsFalse();
    }

    private sealed class Address : SecretAddress
    {
        public string Coordinate => "coordinate";
    }
}
