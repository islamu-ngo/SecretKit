using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments(NativeProvisioningState.Succeeded)]
    [Arguments(NativeProvisioningState.Pending)]
    [Arguments(NativeProvisioningState.Failed)]
    [Arguments(NativeProvisioningState.Canceled)]
    [Arguments(NativeProvisioningState.Unknown)]
    public async Task StatusDeniedPurgeOperationFactoryRemainsFixedWhenStatusKeysAreAdmitted(NativeProvisioningState variant)
    {
        await using var f = new PurgeServiceFixture("denied-authority", statusDeniedPurge: true);
        await Assert.That(() => f.NewSource(deniedStatusOverride: variant)).Throws<InvalidOperationException>();
        await Assert.That(() => f.NewSource(cleanupOnly: true, deniedStatusOverride: variant))
            .Throws<InvalidOperationException>();
        f.Native.Selector = f.Native.Selector with { Variant = "status." + variant };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SetupDeletes + f.SetupPurges + f.SelectedPurges +
            f.ResourceReads + f.IndependentStatusReads).IsEqualTo(0);
    }

    [Test]
    [Arguments(NativeProvisioningState.Succeeded)]
    [Arguments(NativeProvisioningState.Pending)]
    [Arguments(NativeProvisioningState.Failed)]
    [Arguments(NativeProvisioningState.Canceled)]
    [Arguments(NativeProvisioningState.Unknown)]
    public async Task StatusDeniedPurgeStatusRowsRunOriginalDeniedHandler(NativeProvisioningState variant)
    {
        await using var f = new PurgeServiceFixture("denied-authority",
            statusDeniedPurge: true, statusDeniedVariant: variant);
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(f.Native.Selector.Variant).IsEqualTo("status." + variant);
        await Assert.That(tap.Checks.Count).IsEqualTo(1);
        await Assert.That(tap.Checks[0].Task.Result).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tap.Checks[0].Handle.State).IsEqualTo(NativeProvisioningState.Failed);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released && f.Native.Read().Idle).IsTrue();
    }

    [Test]
    [Arguments(NativeProvisioningState.Succeeded, NativeProvisioningState.Pending)]
    [Arguments(NativeProvisioningState.Pending, NativeProvisioningState.Failed)]
    [Arguments(NativeProvisioningState.Failed, NativeProvisioningState.Canceled)]
    [Arguments(NativeProvisioningState.Canceled, NativeProvisioningState.Unknown)]
    [Arguments(NativeProvisioningState.Unknown, NativeProvisioningState.Succeeded)]
    public async Task StatusDeniedPurgeStatusSourceRejectsForeignDeclaredKeyBeforePreparation(
        NativeProvisioningState variant, NativeProvisioningState foreign)
    {
        await using var f = new PurgeServiceFixture("denied-authority",
            statusDeniedPurge: true, statusDeniedVariant: variant);
        f.Native.Selector = f.Native.Selector with { Variant = "status." + foreign };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SetupDeletes + f.SetupPurges + f.SelectedPurges +
            f.ResourceReads + f.IndependentStatusReads).IsEqualTo(0);
    }

    [Test]
    [Arguments(NativeProvisioningState.Succeeded, NativeProvisioningState.Pending)]
    [Arguments(NativeProvisioningState.Pending, NativeProvisioningState.Failed)]
    [Arguments(NativeProvisioningState.Failed, NativeProvisioningState.Canceled)]
    [Arguments(NativeProvisioningState.Canceled, NativeProvisioningState.Unknown)]
    [Arguments(NativeProvisioningState.Unknown, NativeProvisioningState.Succeeded)]
    public async Task StatusDeniedPurgeStatusFactoryRejectsMismatchedProvisioner(
        NativeProvisioningState variant, NativeProvisioningState foreign)
    {
        await using var f = new PurgeServiceFixture("denied-authority",
            statusDeniedPurge: true, statusDeniedVariant: variant);
        await Assert.That(() => f.NewSource(deniedStatusOverride: foreign)).Throws<InvalidOperationException>();
        await Assert.That(() => f.NewSource(cleanupOnly: true, deniedStatusOverride: foreign))
            .Throws<InvalidOperationException>();
        await using var otherParent = f.ReopenProvisioner(foreign);
        await Assert.That(() => f.NewSource(parent: otherParent)).Throws<InvalidOperationException>();
        await Assert.That(f.SetupDeletes + f.SetupPurges + f.SelectedPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusDeniedPurgeStatusFactoriesRejectUndefinedEnumBeforeDispatch()
    {
        await using var f = new PurgeServiceFixture("denied-authority",
            statusDeniedPurge: true, statusDeniedVariant: NativeProvisioningState.Succeeded);
        var invalid = (NativeProvisioningState)int.MaxValue;
        await Assert.That(() => f.NewSource(deniedStatusOverride: invalid)).Throws<InvalidOperationException>();
        await Assert.That(() => f.NewSource(cleanupOnly: true, deniedStatusOverride: invalid))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.ReopenProvisioner(invalid)).Throws<InvalidOperationException>();
        await Assert.That(f.SetupDeletes + f.SetupPurges + f.SelectedPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusDeniedPurgeSelectedMeasurementReportsActualDeletedAbsence()
    {
        await using var f = new PurgeServiceFixture("denied-authority", statusDeniedPurge: true);
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        var measured = await f.Observe(lease);
        await Assert.That(measured.OperationState).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(measured.ResourceStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusDeniedPurgeDisposalJoinsActualDeniedResponseBodyBeforeErasure()
    {
        await using var f = new PurgeServiceFixture("denied-authority", statusDeniedPurge: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        f.Barrier = "original-poll-body";
        var check = f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default).AsTask();
        Task? disposing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            disposing = f.Source.DisposeAsync().AsTask();
            await Assert.That(check.IsCompleted).IsFalse();
            await Assert.That(disposing.IsCompleted).IsFalse();
        }
        finally
        {
            f.Resume.TrySetResult();
            try { await check; }
            catch (OperationCanceledException) { }
            catch (InvalidOperationException) { }
            catch (NativeCaseFailureException) { }
            if (disposing is not null) await disposing.WaitAsync(TimeSpan.FromSeconds(10));
        }
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedPurgeOriginalDeniedClientReadJoinsIndependentRemoteCompletion(bool unauthorized)
    {
        await using var f = new PurgeServiceFixture("denied-authority", statusDeniedPurge: true)
        { Fault = unauthorized ? "denied-selected-unauthorized" : null };
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(1);
        await Assert.That(tap.Checks[0].Task.Result).IsEqualTo(SecretStatus.Denied);
        await Assert.That(ReferenceEquals(tap.Start!.Result.Value, tap.Checks[0].Handle)).IsTrue();
        await Assert.That(tap.Checks[0].Handle.State).IsEqualTo(NativeProvisioningState.Failed);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        var state = f.Native.Read();
        await Assert.That(state.Released && state.Idle && state.Closing && f.Prejournaled).IsTrue();
        await Assert.That(state.Resources.All(r => r.Absent && !r.Borrowed)).IsTrue();
        await Assert.That(state.PurgeDeletedVault!.DeniedStage.ToString()).IsEqualTo("DeniedObserved");
        await Assert.That(state.PurgeDeletedVault.InvocationDispatch).IsEqualTo(state.PurgeDeletedVault.SettledDispatch);
        await Assert.That(state.PurgeDeletedVault.Disposition.ToString()).IsEqualTo("Purged");
    }

    [Test]
    [Arguments("denied-independent-pending")]
    [Arguments("denied-independent-failed")]
    [Arguments("denied-independent-canceled")]
    [Arguments("denied-independent-unknown")]
    [Arguments("denied-independent-denied")]
    [Arguments("denied-independent-malformed")]
    [Arguments("denied-independent-lost")]
    [Arguments("deleted-present")]
    [Arguments("resource-denied")]
    [Arguments("resource-malformed")]
    public async Task StatusDeniedPurgeMissingIndependentCompletionCannotSettleOriginal(string fault)
    {
        await using var f = new PurgeServiceFixture("denied-authority", statusDeniedPurge: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("denied-selected-pending")]
    [Arguments("denied-selected-succeeded")]
    [Arguments("denied-selected-failed")]
    [Arguments("denied-selected-canceled")]
    [Arguments("denied-selected-unknown")]
    [Arguments("denied-selected-absent")]
    [Arguments("denied-selected-malformed")]
    [Arguments("denied-selected-lost")]
    public async Task StatusDeniedPurgeDifferentSelectedResultCannotMintJoinedSettlement(string fault)
    {
        await using var f = new PurgeServiceFixture("denied-authority", statusDeniedPurge: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }
}
