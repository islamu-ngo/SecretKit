using SecretKit.Core;

namespace SecretKit.Core.Tests;

public sealed class MutationReceiptIssuerTests
{
    [Test]
    public async Task PublicCallerCannotSettleAdapterEvidence()
    {
        var target = new SecretReference(new SecretAuthority(), new Address());
        var issuer = new MutationReceiptIssuer();
        var receipt = issuer.Create(target);
        issuer.BeginDispatch(receipt, target);

        // A caller holding evidence must not also hold its writer capability.
        typeof(MutationReceipt).GetMethod("Record")?.Invoke(receipt, [DispatchEvidence.Applied]);

        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(typeof(MutationReceipt).GetConstructors()).IsEmpty();
    }

    [Test]
    public async Task ForeignIssuerCannotDispatchOrSettleOwnedEvidence()
    {
        var target = new SecretReference(new SecretAuthority(), new Address());
        var owner = new MutationReceiptIssuer();
        var foreign = new MutationReceiptIssuer();
        var receipt = owner.Create(target);

        await Assert.That(owner.Owns(receipt)).IsTrue();
        await Assert.That(foreign.Owns(receipt)).IsFalse();
        await Assert.That(() => foreign.BeginDispatch(receipt, target)).Throws<InvalidOperationException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        owner.BeginDispatch(receipt, target);
        await Assert.That(() => foreign.Record(receipt, DispatchEvidence.Applied)).Throws<InvalidOperationException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        owner.Record(receipt, DispatchEvidence.Rejected);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Rejected);
    }

    [Test]
    public async Task ConcurrentDispatchHasExactlyOneWinner()
    {
        var target = new SecretReference(new SecretAuthority(), new Address());
        var issuer = new MutationReceiptIssuer();
        var receipt = issuer.Create(target);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<bool>[] attempts = Enumerable.Range(0, 16).Select(async _ =>
        {
            await start.Task;
            try
            {
                issuer.BeginDispatch(receipt, target);
                return true;
            }
            catch (InvalidOperationException) { return false; }
        }).ToArray();
        start.SetResult();
        bool[] results = await Task.WhenAll(attempts);

        await Assert.That(results.Count(won => won)).IsEqualTo(1);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    private sealed class Address : SecretAddress;
}
