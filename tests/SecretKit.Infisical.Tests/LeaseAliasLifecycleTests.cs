using System.Runtime.CompilerServices;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class LeaseAliasLifecycleTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AliasRevocationInvalidatesEveryHeldCopy(bool inspect)
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        using var lease = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var first = lease.CopyCredentials().Value;
        using var second = lease.CopyCredentials().Value;
        var listed = (await client.ListLeasesAsync(definition)).Value.Items.Single();
        var alias = inspect ? (await client.InspectLeaseAsync(listed.Reference)).Value : listed;
        var receipt = new InfisicalDynamicMutationReceipt(alias.Reference, InfisicalDynamicOperation.Revoke);

        await Assert.That((await client.RevokeLeaseAsync(alias.Reference, receipt)).IsSuccess).IsTrue();

        await Assert.That(wire.LeaseCount).IsEqualTo(0);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(lease.State).IsEqualTo(InfisicalLeaseLocalState.Revoked);
        await Assert.That(() => first.RevealPassword()).Throws<InvalidOperationException>();
        await Assert.That(() => second.RevealUsername()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task AcquisitionJoinsEarlierMetadataAndMetadataOnlyCleanupRemainsUsable()
    {
        using var wire = new DynamicWireFixture();
        await using var seed = wire.Client();
        var original = await wire.CreateDatabaseAsync(seed);
        using var seeded = (await seed.AcquireDatabaseAsync(original, new(original.Target, InfisicalDynamicOperation.Acquire))).Value;
        await using var client = wire.Client();
        var definition = (await client.InspectDefinitionAsync(client.Definition(original.Target.Name))).Value;
        var listed = (await client.ListLeasesAsync(definition)).Value.Items.Single();
        await Assert.That((await client.RenewLeaseAsync(listed,
            new(listed.Reference, InfisicalDynamicOperation.Renew))).IsSuccess).IsTrue();
        wire.RawNextResponse = wire.AcquisitionResponse(seeded.Reference.Id);
        using var acquired = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var copy = acquired.CopyCredentials().Value;
        using var independent = seeded.CopyCredentials().Value;
        string password = independent.RevealPassword();

        await Assert.That((await client.RevokeLeaseAsync(listed.Reference,
            new(listed.Reference, InfisicalDynamicOperation.Revoke))).IsSuccess).IsTrue();

        await Assert.That(acquired.State).IsEqualTo(InfisicalLeaseLocalState.Revoked);
        await Assert.That(() => copy.RevealPassword()).Throws<InvalidOperationException>();
        // Another client's local observation is not authority to change the seed client's state.
        await Assert.That(independent.RevealPassword()).IsEqualTo(password);
    }

    [Test]
    public async Task SameLeaseUuidUnderDifferentDefinitionsDoesNotShareAuthority()
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var firstDefinition = await wire.CreateDatabaseAsync(client);
        var secondDefinition = await wire.CreateDatabaseAsync(client, "second");
        using var first = (await client.AcquireDatabaseAsync(firstDefinition, new(firstDefinition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var second = (await client.AcquireDatabaseAsync(secondDefinition, new(secondDefinition.Target, InfisicalDynamicOperation.Acquire))).Value;
        string secondResponse = wire.AcquisitionResponse(second.Reference.Id).Replace(
            second.Reference.Id.ToString(), first.Reference.Id.ToString(), StringComparison.Ordinal);
        wire.RawNextResponse = secondResponse;
        using var sameUuid = (await client.AcquireDatabaseAsync(secondDefinition,
            new(secondDefinition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var copy = sameUuid.CopyCredentials().Value;
        string password = copy.RevealPassword();

        await Assert.That((await client.RevokeAsync(first, new(first.Reference, InfisicalDynamicOperation.Revoke))).IsSuccess).IsTrue();

        await Assert.That(sameUuid.State).IsEqualTo(InfisicalLeaseLocalState.Active);
        await Assert.That(copy.RevealPassword()).IsEqualTo(password);
    }

    [Test]
    public async Task AliasMutationAdmissionBlocksCompetingMutationCopyAndReveal()
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        using var lease = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var copy = lease.CopyCredentials().Value;
        string exported = copy.RevealPassword();
        var alias = (await client.ListLeasesAsync(definition)).Value.Items.Single();
        var committed = wire.ArmCommitBarrier();
        var renewal = new InfisicalDynamicMutationReceipt(alias.Reference, InfisicalDynamicOperation.Renew);
        var pending = client.RenewLeaseAsync(alias, renewal).AsTask();
        await committed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        int tokens = wire.TokenCalls;
        var revoke = new InfisicalDynamicMutationReceipt(lease.Reference, InfisicalDynamicOperation.Revoke);
        try
        {
            await Assert.That((await client.RevokeAsync(lease, revoke)).Status).IsEqualTo(SecretStatus.Conflict);
            await Assert.That(revoke.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
            await Assert.That(wire.TokenCalls).IsEqualTo(tokens);
            await Assert.That(lease.CopyCredentials().Status).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(() => copy.RevealPassword()).Throws<InvalidOperationException>();
        }
        finally { wire.ReleaseCommit(); await pending; }
        await Assert.That((await pending).IsSuccess).IsTrue();
        await Assert.That(copy.RevealPassword()).IsEqualTo(exported);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task LaterReadsCannotReviveUncertainOrRevokedAliasState(bool revoked)
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        using var lease = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var copy = lease.CopyCredentials().Value;
        var alias = (await client.ListLeasesAsync(definition)).Value.Items.Single();
        string oldRead = wire.LeaseResponse(lease.Reference.Id);
        var operation = revoked ? InfisicalDynamicOperation.Revoke : InfisicalDynamicOperation.Renew;
        var receipt = new InfisicalDynamicMutationReceipt(alias.Reference, operation);
        wire.DropNextMutation = !revoked;
        if (revoked)
            await Assert.That((await client.RevokeLeaseAsync(alias.Reference, receipt)).IsSuccess).IsTrue();
        else
            await Assert.That((await client.RenewLeaseAsync(alias, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        wire.RawNextResponse = oldRead;
        await Assert.That((await client.InspectLeaseAsync(alias.Reference)).IsSuccess).IsTrue();

        await Assert.That(lease.State).IsEqualTo(revoked ? InfisicalLeaseLocalState.Revoked : InfisicalLeaseLocalState.EffectUnknown);
        await Assert.That(() => copy.RevealPassword()).Throws<InvalidOperationException>();
        int tokens = wire.TokenCalls;
        if (revoked)
            await Assert.That((await client.RevokeLeaseAsync(alias.Reference, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        else
            await Assert.That((await client.RenewLeaseAsync(alias, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.TokenCalls).IsEqualTo(tokens);
    }

    [Test]
    [Arguments("version")]
    [Arguments("created")]
    [Arguments("identity")]
    public async Task StaleAliasRenewalCannotAcceptRegressingCanonicalEvidence(string fault)
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        using var lease = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        var stale = (await client.ListLeasesAsync(definition)).Value.Items.Single();
        await client.RenewAsync(lease, new(lease.Reference, InfisicalDynamicOperation.Renew));
        string versionTwo = wire.LeaseResponse(lease.Reference.Id);
        await client.RenewAsync(lease, new(lease.Reference, InfisicalDynamicOperation.Renew));
        if (fault == "created")
        {
            using JsonDocument document = JsonDocument.Parse(versionTwo);
            versionTwo = versionTwo.Replace(document.RootElement.GetProperty("lease").GetProperty("createdAt").GetString()!,
                stale.CreatedAt.AddSeconds(1).ToString("O"), StringComparison.Ordinal);
        }
        else if (fault == "identity")
            versionTwo = versionTwo.Replace(lease.Reference.Id.ToString(), Guid.NewGuid().ToString(), StringComparison.Ordinal);
        wire.RawNextResponse = versionTwo;
        var receipt = new InfisicalDynamicMutationReceipt(stale.Reference, InfisicalDynamicOperation.Renew);

        await Assert.That((await client.RenewLeaseAsync(stale, receipt)).Status).IsEqualTo(SecretStatus.Unknown);

        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(lease.State).IsEqualTo(InfisicalLeaseLocalState.EffectUnknown);
        await Assert.That(lease.Observation.Version).IsEqualTo(3m);
    }

    [Test]
    public async Task StaleAliasUsesSharedDeadlineAndSameVersionRenewalRemainsAccepted()
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        using var lease = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        var stale = (await client.ListLeasesAsync(definition)).Value.Items.Single();
        await client.RenewAsync(lease, new(lease.Reference, InfisicalDynamicOperation.Renew));
        wire.Time.Advance(TimeSpan.FromSeconds(61));
        wire.RawNextResponse = wire.LeaseResponse(lease.Reference.Id);
        var receipt = new InfisicalDynamicMutationReceipt(stale.Reference, InfisicalDynamicOperation.Renew);

        await Assert.That((await client.RenewLeaseAsync(stale, receipt)).IsSuccess).IsTrue();

        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(lease.State).IsEqualTo(InfisicalLeaseLocalState.Active);
        await Assert.That(lease.Observation.Version).IsEqualTo(2m);
    }

    [Test]
    public async Task ReadCannotExtendUsableDeadline()
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        using var lease = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        var alias = (await client.ListLeasesAsync(definition)).Value.Items.Single();
        wire.ObserveLease(lease.Reference.Id, alias.CreatedAt.AddSeconds(120));
        var later = (await client.InspectLeaseAsync(alias.Reference)).Value;
        wire.Time.Advance(TimeSpan.FromSeconds(61));
        int tokens = wire.TokenCalls;

        await Assert.That((await client.RenewLeaseAsync(later, new(later.Reference, InfisicalDynamicOperation.Renew))).Status)
            .IsEqualTo(SecretStatus.Expired);

        await Assert.That(wire.TokenCalls).IsEqualTo(tokens);
        await Assert.That(lease.State).IsEqualTo(InfisicalLeaseLocalState.Expired);
    }

    [Test]
    public async Task ExactReferenceReceiptAuthoritySurvivesSharedLifecycle()
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        using var lease = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        var alias = (await client.ListLeasesAsync(definition)).Value.Items.Single();
        var wrong = new InfisicalDynamicMutationReceipt(lease.Reference, InfisicalDynamicOperation.Revoke);
        int tokens = wire.TokenCalls;

        await Assert.That((await client.RevokeLeaseAsync(alias.Reference, wrong)).Status).IsEqualTo(SecretStatus.Invalid);

        await Assert.That(wrong.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(wire.TokenCalls).IsEqualTo(tokens);
        await Assert.That(wire.LeaseCount).IsEqualTo(1);
        await Assert.That((await client.RevokeLeaseAsync(alias.Reference,
            new(alias.Reference, InfisicalDynamicOperation.Revoke))).IsSuccess).IsTrue();
    }

    [Test]
    public async Task MetadataRenewalOutlivesDisposedWrapperAndExtendsIndependentCopy()
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        using var lease = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var copy = lease.CopyCredentials().Value;
        var metadata = lease.Observation;
        string password = copy.RevealPassword();
        lease.Dispose();
        var disposedReceipt = new InfisicalDynamicMutationReceipt(lease.Reference, InfisicalDynamicOperation.Renew);
        int tokens = wire.TokenCalls;
        await Assert.That((await client.RenewAsync(lease, disposedReceipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.TokenCalls).IsEqualTo(tokens);

        await Assert.That((await client.RenewLeaseAsync(metadata,
            new(metadata.Reference, InfisicalDynamicOperation.Renew))).IsSuccess).IsTrue();

        wire.Time.Advance(TimeSpan.FromSeconds(61));
        await Assert.That(copy.RevealPassword()).IsEqualTo(password);
        await Assert.That(lease.State).IsEqualTo(InfisicalLeaseLocalState.Disposed);
    }

    [Test]
    public async Task RetainedMetadataDoesNotRootDisposedMaterialWrapper()
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        var held = await RetainMetadataAsync(client, definition);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        await Assert.That(held.Wrapper.TryGetTarget(out _)).IsFalse();
        await Assert.That((await client.RevokeLeaseAsync(held.Metadata.Reference,
            new(held.Metadata.Reference, InfisicalDynamicOperation.Revoke))).IsSuccess).IsTrue();
        GC.KeepAlive(held.Metadata);
    }

    [Test]
    public async Task NativeStatusOnAliasBlocksHeldMaterialWithoutRecoveryFromLaterRead()
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        using var lease = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var copy = lease.CopyCredentials().Value;
        wire.ObserveLease(lease.Reference.Id, lease.Observation.ExpiresAt, "pending");
        var alias = (await client.ListLeasesAsync(definition)).Value.Items.Single();
        wire.ObserveLease(lease.Reference.Id, lease.Observation.ExpiresAt);

        await Assert.That((await client.InspectLeaseAsync(alias.Reference)).IsSuccess).IsTrue();

        await Assert.That(lease.State).IsEqualTo(InfisicalLeaseLocalState.EffectUnknown);
        await Assert.That(() => copy.RevealPassword()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task PruningOtherAdmissionsCannotSplitHeldCopyLifecycle()
    {
        using var wire = new DynamicWireFixture();
        await using var client = wire.Client();
        var definition = await wire.CreateDatabaseAsync(client);
        var held = await RetainCopyAsync(client, definition);
        using var copy = held.Copy;
        for (int i = 0; i < 4; i++)
        {
            await RetainMetadataAsync(client, definition);
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }
        var alias = (await client.ListLeasesAsync(definition)).Value.Items.Single(x => x.Reference.Id == held.Id);

        await Assert.That((await client.RevokeLeaseAsync(alias.Reference,
            new(alias.Reference, InfisicalDynamicOperation.Revoke))).IsSuccess).IsTrue();

        await Assert.That(() => copy.RevealPassword()).Throws<InvalidOperationException>();
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<(Guid Id, InfisicalDatabaseCredentials Copy)> RetainCopyAsync(
        InfisicalDynamicClient client, InfisicalDynamicDefinition definition)
    {
        using var lease = (await client.AcquireDatabaseAsync(definition, new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        return (lease.Reference.Id, lease.CopyCredentials().Value);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<(InfisicalLeaseObservation Metadata, WeakReference<InfisicalDatabaseLease> Wrapper)>
        RetainMetadataAsync(InfisicalDynamicClient client, InfisicalDynamicDefinition definition)
    {
        InfisicalDatabaseLease? lease = (await client.AcquireDatabaseAsync(definition,
            new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        var retained = (lease.Observation, new WeakReference<InfisicalDatabaseLease>(lease));
        lease.Dispose();
        // The completed async helper itself must not keep the object under collection alive.
        lease = null;
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        return retained;
    }
}
