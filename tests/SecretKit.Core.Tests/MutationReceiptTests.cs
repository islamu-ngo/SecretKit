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
        var issuer = new MutationReceiptIssuer();
        var receipt = issuer.Create(target);

        await Assert.That(() => issuer.BeginDispatch(receipt, other)).Throws<InvalidOperationException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        issuer.BeginDispatch(receipt, target);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(() => issuer.BeginDispatch(receipt, target)).Throws<InvalidOperationException>();
        issuer.Record(receipt, DispatchEvidence.Applied);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(() => issuer.Record(receipt, DispatchEvidence.Rejected)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task UnknownEffectCannotBeResetToNoDispatch()
    {
        var target = new SecretReference(new SecretAuthority(), new Address());
        var issuer = new MutationReceiptIssuer();
        var receipt = issuer.Create(target);
        issuer.BeginDispatch(receipt, target);

        await Assert.That(() => issuer.Record(receipt, DispatchEvidence.NotDispatched)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(JsonSerializer.Serialize(receipt).Contains("coordinate", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(receipt).Contains(receipt.LocalId.ToString(), StringComparison.Ordinal)).IsFalse();
    }

    private sealed class Address : SecretAddress
    {
        public string Coordinate => "coordinate";
    }
}
