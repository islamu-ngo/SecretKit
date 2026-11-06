using System.Net;
using SecretKit.Core;
using SecretKit.Infisical.Dynamic;

namespace SecretKit.Infisical.Tests;

public sealed class DefinitionLifecycleTests
{
    [Test]
    public async Task DefinitionDeletionInvalidatesEveryHeldCopy()
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        using var first = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var second = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var firstCopy = first.CopyCredentials().Value;
        using var secondCopy = second.CopyCredentials().Value;
        var alias = (await client.ListDefinitionsAsync()).Value.Items.Single();
        string prior = wire.DefinitionResponse(definition.Target.Name);
        var receipt = new InfisicalDynamicMutationReceipt(alias.Target, InfisicalDynamicOperation.DeleteDefinition);

        await Assert.That((await client.DeleteDefinitionAsync(alias, receipt)).IsSuccess).IsTrue();

        await Assert.That(wire.DefinitionCount).IsEqualTo(0);
        await Assert.That(wire.LeaseCount).IsEqualTo(0);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(first.State).IsEqualTo(InfisicalLeaseLocalState.Revoked);
        await Assert.That(second.State).IsEqualTo(InfisicalLeaseLocalState.Revoked);
        await Assert.That(() => firstCopy.RevealUsername()).Throws<InvalidOperationException>();
        await Assert.That(() => secondCopy.RevealPassword()).Throws<InvalidOperationException>();
        wire.RawNextResponse = prior;
        var later = (await client.InspectDefinitionAsync(definition.Target)).Value;
        int tokens = wire.TokenCalls;
        await Assert.That((await client.AcquireDatabaseAsync(later, new(later.Target, InfisicalDynamicOperation.Acquire))).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.TokenCalls).IsEqualTo(tokens);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task LostParentMutationBlocksExportsAndAllowsFreshUuidCleanupWithoutRecovery(bool rename)
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        using var first = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var second = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var copy = second.CopyCredentials().Value;
        string prior = wire.DefinitionResponse(definition.Target.Name);
        var operation = rename ? InfisicalDynamicOperation.UpdateDefinition : InfisicalDynamicOperation.DeleteDefinition;
        var receipt = new InfisicalDynamicMutationReceipt(definition.Target, operation);
        wire.DropNextMutation = true;

        await Assert.That(await MutateParentAsync(client, definition, receipt, rename)).IsEqualTo(SecretStatus.Unknown);

        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(second.State).IsEqualTo(InfisicalLeaseLocalState.EffectUnknown);
        await Assert.That(() => copy.RevealPassword()).Throws<InvalidOperationException>();
        int tokens = wire.TokenCalls;
        await Assert.That(await MutateParentAsync(client, definition, receipt, rename)).IsEqualTo(SecretStatus.Invalid);
        await Assert.That((await client.RenewAsync(first, new(first.Reference, InfisicalDynamicOperation.Renew))).Status)
            .IsEqualTo(SecretStatus.Unknown);
        await Assert.That(wire.TokenCalls).IsEqualTo(tokens);
        wire.RawNextResponse = prior;
        var read = (await client.InspectDefinitionAsync(definition.Target)).Value;
        tokens = wire.TokenCalls;
        await Assert.That((await client.AcquireDatabaseAsync(read, new(read.Target, InfisicalDynamicOperation.Acquire))).Status)
            .IsEqualTo(SecretStatus.Unknown);
        await Assert.That(wire.TokenCalls).IsEqualTo(tokens);
        var cleanup = new InfisicalDynamicMutationReceipt(first.Reference, InfisicalDynamicOperation.Revoke);
        var cleaned = await client.RevokeLeaseAsync(first.Reference, cleanup);
        await Assert.That(cleaned.Status).IsEqualTo(rename ? SecretStatus.Success : SecretStatus.Absent);
        await Assert.That(wire.TokenCalls).IsEqualTo(tokens + 1);
        await Assert.That(cleanup.Evidence).IsEqualTo(rename ? DispatchEvidence.Applied : DispatchEvidence.Rejected);
        await Assert.That(second.State).IsEqualTo(InfisicalLeaseLocalState.EffectUnknown);
        await Assert.That(() => copy.RevealPassword()).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(false, HttpStatusCode.Forbidden)]
    [Arguments(false, HttpStatusCode.Conflict)]
    [Arguments(true, HttpStatusCode.Forbidden)]
    [Arguments(true, HttpStatusCode.Conflict)]
    public async Task RejectedParentMutationPreservesMaterialAndReleasesAdmission(bool rename, HttpStatusCode status)
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        using var lease = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var copy = lease.CopyCredentials().Value;
        string password = copy.RevealPassword();
        wire.RawNextResponse = "{}";
        wire.StatusNextResponse = status;
        var receipt = new InfisicalDynamicMutationReceipt(definition.Target,
            rename ? InfisicalDynamicOperation.UpdateDefinition : InfisicalDynamicOperation.DeleteDefinition);

        await Assert.That(await MutateParentAsync(client, definition, receipt, rename))
            .IsEqualTo(status == HttpStatusCode.Conflict ? SecretStatus.Conflict : SecretStatus.Denied);

        await Assert.That(copy.RevealPassword()).IsEqualTo(password);
        await Assert.That(lease.State).IsEqualTo(InfisicalLeaseLocalState.Active);
        using var next = (await client.AcquireDatabaseAsync(definition,
            new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        await Assert.That(wire.LeaseCount).IsEqualTo(2);
    }

    [Test]
    [Arguments(InfisicalDynamicOperation.Acquire, false)]
    [Arguments(InfisicalDynamicOperation.Renew, false)]
    [Arguments(InfisicalDynamicOperation.Revoke, false)]
    [Arguments(InfisicalDynamicOperation.UpdateDefinition, false)]
    [Arguments(InfisicalDynamicOperation.Acquire, true)]
    [Arguments(InfisicalDynamicOperation.Renew, true)]
    [Arguments(InfisicalDynamicOperation.Revoke, true)]
    [Arguments(InfisicalDynamicOperation.UpdateDefinition, true)]
    public async Task AdmittedChildBlocksExclusiveParentBeforeCredentials(InfisicalDynamicOperation operation, bool rename)
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        var other = await wire.CreateDatabaseAsync(client, "other");
        using var lease = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        var entered = wire.ArmCommitBarrier();
        var pending = InvokeChildAsync(client, definition, lease, operation);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var receipt = new InfisicalDynamicMutationReceipt(definition.Target,
            rename ? InfisicalDynamicOperation.UpdateDefinition : InfisicalDynamicOperation.DeleteDefinition);
        int tokens = wire.TokenCalls;
        try
        {
            await Assert.That(await MutateParentAsync(client, definition, receipt, rename)).IsEqualTo(SecretStatus.Conflict);
            await Assert.That(wire.TokenCalls).IsEqualTo(tokens);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
            using var unrelated = (await client.AcquireDatabaseAsync(other, new(other.Target, InfisicalDynamicOperation.Acquire))).Value;
            await Assert.That(unrelated.State).IsEqualTo(InfisicalLeaseLocalState.Active);
        }
        finally { wire.ReleaseCommit(); await pending; }
        await Assert.That(await pending).IsEqualTo(SecretStatus.Success);
        await Assert.That(await MutateParentAsync(client, definition, receipt, rename)).IsEqualTo(SecretStatus.Success);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ExclusiveParentBlocksEveryChildAndMaterialExportBeforeCredentials(bool rename)
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        using var lease = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var copy = lease.CopyCredentials().Value;
        var entered = wire.ArmCommitBarrier();
        var receipt = new InfisicalDynamicMutationReceipt(definition.Target,
            rename ? InfisicalDynamicOperation.UpdateDefinition : InfisicalDynamicOperation.DeleteDefinition);
        var pending = MutateParentAsync(client, definition, receipt, rename);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        int tokens = wire.TokenCalls;
        try
        {
            foreach (var operation in new[] { InfisicalDynamicOperation.Acquire, InfisicalDynamicOperation.Renew,
                InfisicalDynamicOperation.Revoke, InfisicalDynamicOperation.UpdateDefinition })
                await Assert.That(await InvokeChildAsync(client, definition, lease, operation)).IsEqualTo(SecretStatus.Conflict);
            await Assert.That(wire.TokenCalls).IsEqualTo(tokens);
            await Assert.That(lease.CopyCredentials().Status).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(() => copy.RevealPassword()).Throws<InvalidOperationException>();
        }
        finally { wire.ReleaseCommit(); await pending; }
        await Assert.That(await pending).IsEqualTo(SecretStatus.Success);
    }

    [Test]
    public async Task ExclusiveAdmissionWaitsForEveryCountedChildToSettle()
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        var firstEntered = wire.ArmCommitBarrier();
        var firstRelease = wire.CommitRelease;
        var first = client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire)).AsTask();
        await firstEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var secondEntered = wire.ArmCommitBarrier();
        var secondRelease = wire.CommitRelease;
        var second = client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire)).AsTask();
        try
        {
            await secondEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            firstRelease.TrySetResult();
            using var firstLease = (await first).Value;
            int tokens = wire.TokenCalls;
            await Assert.That((await client.DeleteDefinitionAsync(definition,
                new(definition.Target, InfisicalDynamicOperation.DeleteDefinition))).Status).IsEqualTo(SecretStatus.Conflict);
            await Assert.That(wire.TokenCalls).IsEqualTo(tokens);
        }
        finally
        {
            firstRelease.TrySetResult();
            secondRelease.TrySetResult();
            using var firstLease = (await first).Value;
            using var secondLease = (await second).Value;
        }
        await Assert.That((await client.DeleteDefinitionAsync(definition,
            new(definition.Target, InfisicalDynamicOperation.DeleteDefinition))).IsSuccess).IsTrue();
    }

    [Test]
    [Arguments(InfisicalDynamicOperation.Acquire, false)]
    [Arguments(InfisicalDynamicOperation.UpdateDefinition, false)]
    [Arguments(InfisicalDynamicOperation.DeleteDefinition, false)]
    [Arguments(InfisicalDynamicOperation.Acquire, true)]
    [Arguments(InfisicalDynamicOperation.UpdateDefinition, true)]
    [Arguments(InfisicalDynamicOperation.DeleteDefinition, true)]
    public async Task StaleNameAddressedHandleFailsPreCredentialAfterRename(
        InfisicalDynamicOperation operation, bool responseLost)
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var original = await wire.CreateDatabaseAsync(client);
        using var originalLease = (await client.AcquireDatabaseAsync(original, new(original.Target, InfisicalDynamicOperation.Acquire))).Value;
        wire.DropNextMutation = responseLost;
        var renamed = await client.UpdateDefinitionAsync(original, new(newName: "renamed"),
            new(original.Target, InfisicalDynamicOperation.UpdateDefinition));
        await Assert.That(renamed.Status).IsEqualTo(responseLost ? SecretStatus.Unknown : SecretStatus.Success);
        var replacement = await wire.CreateDatabaseAsync(client);
        using var replacementLease = (await client.AcquireDatabaseAsync(replacement,
            new(replacement.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var replacementCopy = replacementLease.CopyCredentials().Value;
        string password = replacementCopy.RevealPassword();
        var receipt = new InfisicalDynamicMutationReceipt(original.Target, operation);
        int tokens = wire.TokenCalls;
        int sends = wire.SendCount;

        SecretStatus result;
        if (operation == InfisicalDynamicOperation.DeleteDefinition)
            result = (await client.DeleteDefinitionAsync(original, receipt)).Status;
        else if (operation == InfisicalDynamicOperation.UpdateDefinition)
            result = (await client.UpdateDefinitionAsync(original, new(defaultTtl: new(TimeSpan.FromSeconds(30))), receipt)).Status;
        else
        {
            var acquired = await client.AcquireDatabaseAsync(original, receipt);
            using var unexpected = acquired.IsSuccess ? acquired.Value : null;
            result = acquired.Status;
        }

        await Assert.That(result).IsEqualTo(responseLost ? SecretStatus.Unknown : SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(wire.TokenCalls).IsEqualTo(tokens);
        await Assert.That(wire.SendCount).IsEqualTo(sends);
        await Assert.That(wire.DefinitionCount).IsEqualTo(2);
        await Assert.That(wire.LeaseCount).IsEqualTo(2);
        await Assert.That(replacementCopy.RevealPassword()).IsEqualTo(password);
        var unchanged = (await client.InspectDefinitionAsync(replacement.Target)).Value;
        await Assert.That(unchanged.Id).IsEqualTo(replacement.Id);
        await Assert.That(unchanged.Version).IsEqualTo(replacement.Version);
    }

    private static async Task<SecretStatus> MutateParentAsync(InfisicalDynamicClient client,
        InfisicalDynamicDefinition definition, InfisicalDynamicMutationReceipt receipt, bool rename) =>
        rename
            ? (await client.UpdateDefinitionAsync(definition, new(newName: "renamed"), receipt)).Status
            : (await client.DeleteDefinitionAsync(definition, receipt)).Status;

    private static async Task<SecretStatus> InvokeChildAsync(InfisicalDynamicClient client,
        InfisicalDynamicDefinition definition, InfisicalDatabaseLease lease, InfisicalDynamicOperation operation)
    {
        switch (operation)
        {
            case InfisicalDynamicOperation.Acquire:
                var acquired = await client.AcquireDatabaseAsync(definition, new(definition.Target, operation));
                using (var material = acquired.IsSuccess ? acquired.Value : null) { return acquired.Status; }
            case InfisicalDynamicOperation.UpdateDefinition:
                return (await client.UpdateDefinitionAsync(definition,
                    new(defaultTtl: new(TimeSpan.FromSeconds(30))), new(definition.Target, operation))).Status;
            case InfisicalDynamicOperation.Renew:
                return (await client.RenewAsync(lease, new(lease.Reference, operation))).Status;
            case InfisicalDynamicOperation.Revoke:
                return (await client.RevokeLeaseAsync(lease.Reference, new(lease.Reference, operation))).Status;
            default:
                throw new InvalidOperationException("Unexpected child operation.");
        }
    }
}
