using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Op = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;
using Service = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task StatusSucceededDeleteVaultCancellationOriginalHandlerUsesDistinctProfileAndTwoActualChecks()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true);
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Start!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(tap.StartReceipt).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(tap.Checks.Count).IsEqualTo(2);
        await Assert.That(tap.Checks[0].Canceled).IsTrue();
        await Assert.That(tap.Checks[0].Task.IsCanceled).IsTrue();
        await Assert.That(tap.Checks[1].Canceled).IsFalse();
        await Assert.That(ReferenceEquals(tap.Checks[0].Task, tap.Checks[1].Task)).IsFalse();
        await Assert.That(tap.Checks[1].Task.Result).IsEqualTo(SecretStatus.Success);
        await Assert.That(ReferenceEquals(tap.Start.Result.Value, tap.Checks[1].Handle)).IsTrue();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads + f.OriginalResourceReads + f.SetupDeletes + f.SelectedPurges).IsEqualTo(0);
        await Assert.That(f.SucceededBaselineReads >= 2 && f.SucceededSelectedReads >= 2).IsTrue();
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        var state = f.Native.Read();
        await Assert.That(state.Released && state.Idle && f.Prejournaled).IsTrue();
        await Assert.That(state.Resources.Length).IsEqualTo(3);
        await Assert.That(state.Selector.Variant).IsEqualTo("status.Succeeded");
        await Assert.That(state.StatusSucceededDeleteVault!.Operation).IsEqualTo(ManagementMutation.DeleteVault);
        await Assert.That(state.StatusSucceededDeleteVault.InvocationDispatch).IsNotEqualTo(Guid.Empty);
        await Assert.That(state.StatusSucceededDeleteVault.SettledDispatch).IsEqualTo(state.StatusSucceededDeleteVault.InvocationDispatch);
        await Assert.That(f.Native.Wire.Secret).IsNull();
        await Assert.That(state.Resources.Single(r => r.Id == f.Plan().VaultId).DeleteAttempted).IsFalse();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("delete-202")]
    [Arguments("synchronous")]
    [Arguments("selected-malformed")]
    [Arguments("no-target")]
    public async Task StatusSucceededDeleteVaultCancellationRequiresCapturedOriginalPending200AndTarget(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true)
        { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().StatusSucceededDeleteVault!.SettledDispatch).IsEqualTo(Guid.Empty);
    }

    [Test]
    [Arguments("pending")]
    [Arguments("unknown")]
    [Arguments("failed")]
    [Arguments("canceled")]
    [Arguments("status-malformed")]
    [Arguments("status-denied")]
    public async Task StatusSucceededDeleteVaultCancellationLabelDoesNotSupplyIndependentNativeStatus(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true)
        { Fault = fault };
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(tap.Checks.Count).IsEqualTo(0);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("deleted-missing")]
    [Arguments("deleted-foreign")]
    [Arguments("deleted-protected")]
    [Arguments("deleted-malformed")]
    [Arguments("active-reappeared")]
    [Arguments("resource-denied")]
    [Arguments("resource-malformed")]
    public async Task StatusSucceededDeleteVaultCancellationRequiresBothIndependentNativeResourceReads(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true)
        { Fault = fault };
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsFalse();
        await Assert.That(f.ResourceFaultsReached > 0).IsTrue();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(tap.Checks.Count).IsEqualTo(0);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().StatusSucceededDeleteVault!.SettledDispatch).IsEqualTo(Guid.Empty);
    }

    [Test]
    [Arguments("tag")]
    [Arguments("tenant")]
    [Arguments("private")]
    [Arguments("policy")]
    [Arguments("network")]
    [Arguments("uri")]
    [Arguments("retention")]
    public async Task StatusSucceededDeleteVaultCancellationBaselineRequiresFullOwnedConfiguration(string field)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true);
        var lease = await f.Observer.PostAsync<Op.Prepare, Op.Lease>("operation/prepare", f.PrepareRequest(), default);
        f.Armed = await f.Observer.SubscribeAsync("operation", lease.Facts, default);
        f.SucceededBaselineTransform = row =>
        {
            switch (field)
            {
                case "tag": row["tags"] = new JsonObject { ["secretkit-fixture"] = Guid.NewGuid().ToString("N") }; break;
                case "tenant": row["properties"]!["tenantId"] = Guid.NewGuid().ToString(); break;
                case "private": row["properties"]!.AsObject().Remove("privateEndpointConnections"); break;
                case "policy": row["properties"]!.AsObject().Remove("accessPolicies"); break;
                case "network": row["properties"]!["publicNetworkAccess"] = "Disabled"; break;
                case "uri": row["properties"]!["vaultUri"] = "https://foreign.vault.azure.net"; break;
                default: row["properties"]!["softDeleteRetentionInDays"] = 7; break;
            }
        };
        await Assert.That(async () => await f.Observer.PostAsync<ObserveLease, Op.Measurement>("operation/observe",
            new(lease.Facts.LeaseId, lease.Facts.Nonce, "baseline-before-dispatch", f.Armed.SubscriptionId), default))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.SucceededResourceMutations).IsEqualTo(1);
        await Assert.That(f.SelectedDeletes).IsEqualTo(0);
        await Assert.That(f.Native.Read().StatusSucceededDeleteVault!.InvocationDispatch).IsEqualTo(Guid.Empty);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    public async Task StatusSucceededDeleteVaultCancellationFactoryRejectsOtherCasesBeforeDeclaration(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, ManagementMutation.DeleteVault,
            statusSucceededDeleteVaultCancellation: true);
        await Assert.That(async () => await f.Observer.PostAsync<Op.Prepare, Op.Lease>(
            "operation/prepare", f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    [Arguments(ManagementMutation.PurgeDeletedVault)]
    [Arguments(ManagementMutation.RecoverVault)]
    public async Task StatusSucceededDeleteVaultCancellationRejectsWrongPrepareOperationBeforeDeclaration(ManagementMutation operation)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true);
        var request = f.PrepareRequest() with { Operation = operation };
        await Assert.That(async () => await f.Observer.PostAsync<Op.Prepare, Op.Lease>("operation/prepare", request, default))
            .Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    public async Task StatusSucceededDeleteVaultCancellationRejectsWrongOriginalInputBeforeSelection()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true);
        var lease = await f.PrepareAndBaseline();
        f.input = f.input with { StatusOperation = ManagementMutation.PurgeDeletedVault };
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedDeletes).IsEqualTo(0);
        await Assert.That(f.Native.Read().StatusSucceededDeleteVault!.InvocationDispatch).IsEqualTo(Guid.Empty);
    }

    [Test]
    public async Task StatusSucceededDeleteVaultCancellationCannotUseCopiedOrGenericCertificates()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var id = f.Plan().VaultId;
        await Assert.That(() => f.Native.Journal.BeginStatusSucceededDeleteVaultCancellationInvocation(Owner,
            f.Native.Selector, lease.Facts.LeaseId, new Service.StatusSucceededDeleteVaultCancellationAdmission(f.Source)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.BeginSelectedDispatch(Owner, f.Native.Selector, id, delete: true))
            .Throws<InvalidOperationException>();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var dispatch = f.Native.Read().StatusSucceededDeleteVault!.InvocationDispatch;
        await Assert.That(() => f.Native.Journal.AdmitStatusRead(Owner, f.Native.Selector, lease.Facts.LeaseId, id, dispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, id, dispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, id, dispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.CompleteStatusSucceededDeleteVaultCancellationRead(Owner, f.Native.Selector,
            lease.Facts.LeaseId, dispatch, new Service.StatusSucceededDeleteVaultCancellationSettlement(f.Source)))
            .Throws<InvalidOperationException>();
        await CompleteSucceededCancellation(f, started.Value!);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusSucceededDeleteVaultCancellationSelectedDeletedReadRejectsForeignOwnership()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true);
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        f.SucceededSelectedTransform = row =>
        {
            if (row["properties"]?["vaultId"] is not null)
                row["properties"]!["tags"]!["secretkit-fixture"] = Guid.NewGuid().ToString("N");
        };
        await Assert.That(async () => await f.Observe(lease)).Throws<NativeCaseFailureException>();
        await Assert.That(f.SucceededResourceMutations).IsEqualTo(1);
        await Assert.That(f.Native.Read().StatusSucceededDeleteVault!.SettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusSucceededDeleteVaultCancellationRetainedCommittedRetryIsReadOnly()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault,
            statusSucceededDeleteVaultCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await CompleteSucceededCancellation(f, started.Value!);
        var committed = f.Native.Read();
        int reads = f.ResourceReads + f.IndependentStatusReads + f.OriginalStatusReads + f.OriginalResourceReads;
        f.Source.RetryStatusSucceededDeleteVaultCancellationPersistence(f.Native.Selector);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(committed.Revision);
        await Assert.That(f.ResourceReads + f.IndependentStatusReads + f.OriginalStatusReads + f.OriginalResourceReads).IsEqualTo(reads);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusSucceededDeleteVaultCancellationRetryCannotRefreshAuthorityAfterClose()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault,
            statusSucceededDeleteVaultCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await CompleteSucceededCancellation(f, started.Value!);
        f.Native.Journal.Close(Owner, f.Native.Selector);
        long closed = f.Native.Read().Revision;
        int reads = f.ResourceReads + f.IndependentStatusReads + f.OriginalStatusReads + f.OriginalResourceReads;
        await Assert.That(() => f.Source.RetryStatusSucceededDeleteVaultCancellationPersistence(f.Native.Selector))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Revision).IsEqualTo(closed);
        await Assert.That(f.ResourceReads + f.IndependentStatusReads + f.OriginalStatusReads + f.OriginalResourceReads).IsEqualTo(reads);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusSucceededDeleteVaultCancellationForeignHandleCannotStealOneCheck()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true);
        await using var other = new PurgeServiceFixture(operation: ManagementMutation.DeleteVault);
        var lease = await f.PrepareAndBaseline();
        var foreignLease = await other.PrepareAndBaseline();
        var started = await f.Start(lease);
        var foreign = await other.Start(foreignLease);
        await f.Observe(lease);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, foreign.Value!, default))
            .Throws<InvalidOperationException>();
        await CompleteSucceededCancellation(f, started.Value!);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selected-credential")]
    [Arguments("selected-send")]
    [Arguments("selected-body")]
    [Arguments("selected-sdk")]
    [Arguments("status-credential")]
    [Arguments("status-send")]
    [Arguments("resource-body")]
    public async Task StatusSucceededDeleteVaultCancellationCloseDrainsActualBorrower(string barrier)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true);
        var lease = await f.PrepareAndBaseline();
        Task work;
        if (barrier.StartsWith("selected-", StringComparison.Ordinal))
        {
            f.Barrier = barrier;
            work = f.Start(lease);
        }
        else
        {
            await f.Start(lease);
            f.Barrier = barrier;
            work = f.Observe(lease).AsTask();
        }
        Task? disposal = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await f.Release();
            disposal = f.Source.DisposeAsync().AsTask();
            await Assert.That(work.IsCompleted || disposal.IsCompleted).IsFalse();
            await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception ex) when (ex is OperationCanceledException or InvalidOperationException or NativeCaseFailureException) { }
        await disposal!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().StatusSucceededDeleteVault!.SettledDispatch).IsEqualTo(Guid.Empty);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusSucceededDeleteVaultCancellationRestartCannotInventSettlement(bool settled)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        if (settled) await CompleteSucceededCancellation(f, started.Value!);
        var dispatch = f.Native.Read().StatusSucceededDeleteVault!.InvocationDispatch;
        await f.Source.DisposeAsync();
        await using var parent = f.ReopenProvisioner();
        await using var source = f.NewSource(cleanupOnly: true, parent: parent);
        using var observer = f.NewObserver(source);
        var result = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>("operation/release", f.Native.Selector, default);
        await Assert.That(f.Native.Read().Released).IsEqualTo(settled);
        if (settled) RoleFixtureRelease.Validate(result, f.Native.Selector, lease.Facts);
        else await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Plan().VaultId).ActiveDispatch).IsEqualTo(dispatch);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(0);
        await Assert.That(f.SetupPurges).IsEqualTo(settled ? 1 : 0);
    }

    [Test]
    [Arguments("cleanup-active-present")]
    [Arguments("cleanup-active-empty")]
    [Arguments("cleanup-active-malformed")]
    [Arguments("cleanup-deleted-forbidden")]
    public async Task StatusSucceededDeleteVaultCancellationFreshCleanupCannotBorrowOldAbsence(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await CompleteSucceededCancellation(f, started.Value!);
        f.Fault = fault;
        await Assert.That((await f.Release()).RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.CleanupFaultsReached > 0).IsTrue();
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task StatusSucceededDeleteVaultCancellationCloseFirstCannotPublishOldCompletion()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        f.Native.Journal.Close(Owner, f.Native.Selector);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await f.Release();
        await Assert.That(f.Native.Read().StatusSucceededDeleteVault!.SettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    public async Task StatusSucceededDeleteVaultCancellationNeverSelectedReplyLossUsesOnlyGuardedSetupCleanup(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true)
        { PrepareReplyFault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    public async Task StatusSucceededDeleteVaultCancellationReplayRejectsSecondTerminatedCleanupInvocation()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault, statusSucceededDeleteVaultCancellation: true);
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        byte[] history = File.ReadAllBytes(f.Native.JournalPath);
        int offset = 0, cut = 0;
        long sequence = 0;
        string? previous = null;
        RoleFixtureJournal.Snapshot? candidate = null;
        while (offset < history.Length)
        {
            int length = BinaryPrimitives.ReadInt32LittleEndian(history.AsSpan(offset, 4));
            var payload = history.AsMemory(offset + 4, length);
            using var frame = JsonDocument.Parse(payload);
            var state = frame.RootElement.GetProperty("state").Deserialize<RoleFixtureJournal.Snapshot>(ManagementAdmission.Json)!;
            var marker = state.Resources.Single(r => r.Id == f.Plan().DeletedId);
            if (state.Closing && marker is { DeleteAttempted: true, InvocationTerminated: true, Absent: false } &&
                marker.ActiveDispatch == Guid.Empty)
            {
                candidate = state with
                {
                    Revision = state.Revision + 1,
                    Resources = state.Resources.Select(r => r.Id == marker.Id
                        ? r with { ActiveDispatch = Guid.NewGuid(), InvocationTerminated = false, Absent = false }
                        : r with { Absent = false }).ToArray()
                };
                sequence = frame.RootElement.GetProperty("sequence").GetInt64() + 1;
                previous = Convert.ToHexString(SHA256.HashData(payload.Span));
                cut = offset + 4 + length + 32;
                break;
            }
            offset += 4 + length + 32;
        }
        await Assert.That(candidate).IsNotNull();
        byte[] forged = JsonSerializer.SerializeToUtf8Bytes(
            new StatusSucceededCancellationReplayFrame(sequence, previous!, candidate!), ManagementAdmission.Json);
        await using (var file = new FileStream(f.Native.JournalPath, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            file.SetLength(cut);
            file.Position = cut;
            byte[] prefix = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(prefix, forged.Length);
            await file.WriteAsync(prefix);
            await file.WriteAsync(forged);
            await file.WriteAsync(SHA256.HashData(forged));
        }
        var reopened = new RoleFixtureJournal(Path.GetDirectoryName(f.Native.JournalPath)!);
        try
        {
            await Assert.That(() => reopened.Read(Owner, f.Native.Selector)).Throws<InvalidOperationException>();
        }
        finally { await File.WriteAllBytesAsync(f.Native.JournalPath, history); }
    }

    [Test]
    public async Task StatusSucceededDeleteVaultCancellationRetainsExactSixTransitionRevisions()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault,
            statusSucceededDeleteVaultCancellation: true);
        var lease = await f.PrepareAndBaseline();
        long baseline = f.Native.Read().Revision;
        var started = await f.Start(lease);
        var drained = f.Native.Read();
        await Assert.That(drained.Revision).IsEqualTo(baseline + 2);
        var dispatch = drained.StatusSucceededDeleteVault!.InvocationDispatch;
        await f.Observe(lease);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(drained.Revision);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        var canceled = f.Native.Read();
        await Assert.That(canceled.Revision).IsEqualTo(baseline + 4);
        await Assert.That(canceled.StatusSucceededDeleteVault!.SettledDispatch).IsEqualTo(Guid.Empty);
        var row = canceled.Resources.Single(r => r.Id == f.Plan().VaultId);
        await Assert.That(row.InvocationTerminated && row.ActiveDispatch == dispatch).IsTrue();
        int reads = f.ResourceReads + f.IndependentStatusReads;
        f.Source.RetryStatusSucceededDeleteVaultCancellationPersistence(f.Native.Selector);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(canceled.Revision);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default)).IsEqualTo(SecretStatus.Success);
        var committed = f.Native.Read();
        await Assert.That(committed.Revision).IsEqualTo(baseline + 6);
        await Assert.That(committed.StatusSucceededDeleteVault!.SettledDispatch).IsEqualTo(dispatch);
        await Assert.That(f.ResourceReads + f.IndependentStatusReads).IsEqualTo(reads);
        await Assert.That(f.OriginalStatusReads + f.OriginalResourceReads).IsEqualTo(0);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusSucceededDeleteVaultCancellationCloseAfterCanceledDrainCannotAdmitLaterCheck()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault,
            statusSucceededDeleteVaultCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        f.Native.Journal.Close(Owner, f.Native.Selector);
        long closed = f.Native.Read().Revision;
        await Assert.That(() => f.Source.RetryStatusSucceededDeleteVaultCancellationPersistence(f.Native.Selector))
            .Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Revision).IsEqualTo(closed);
        await f.Release();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusSucceededDeleteVaultCancellationObservationCallerRemainsAVetoAfterResponse()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault,
            statusSucceededDeleteVaultCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        using var observation = new CancellationTokenSource();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://purge-observer.example/operation/observe");
        request.Headers.Authorization = new("Bearer", "private-purge-service-capability");
        request.Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(new ObserveLease(lease.Facts.LeaseId,
            lease.Facts.Nonce, "selected-state", f.Armed!.SubscriptionId),
            new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
        request.Content.Headers.ContentType = new("application/json");
        using var response = await f.Source.DispatchAsync(request, observation.Token);
        await Assert.That(response.IsSuccessStatusCode).IsTrue();
        observation.Cancel();
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, canceled.Token))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().StatusSucceededDeleteVault!.SettledDispatch).IsEqualTo(Guid.Empty);
        await f.Release();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusSucceededDeleteVaultCancellationMalformedHistoryPermanentlyRevokesRetry()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault,
            statusSucceededDeleteVaultCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await CompleteSucceededCancellation(f, started.Value!);
        var state = f.Native.Read();
        byte[] history = File.ReadAllBytes(f.Native.JournalPath);
        int offset = 0;
        byte[]? last = null;
        long sequence = 0;
        while (offset < history.Length)
        {
            int size = BinaryPrimitives.ReadInt32LittleEndian(history.AsSpan(offset, 4));
            last = history.AsSpan(offset + 4, size).ToArray();
            using var frame = JsonDocument.Parse(last);
            sequence = frame.RootElement.GetProperty("sequence").GetInt64();
            offset += size + 36;
        }
        var malformed = state with { Resources = [null!, .. state.Resources.Skip(1)] };
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new StatusSucceededCancellationReplayFrame(
            sequence + 1, Convert.ToHexString(SHA256.HashData(last!)), malformed), ManagementAdmission.Json);
        try
        {
            await using (var file = new FileStream(f.Native.JournalPath, FileMode.Append, FileAccess.Write, FileShare.None))
            {
                byte[] prefix = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
                await file.WriteAsync(prefix);
                await file.WriteAsync(payload);
                await file.WriteAsync(SHA256.HashData(payload));
            }
            await Assert.That(() => f.Source.RetryStatusSucceededDeleteVaultCancellationPersistence(f.Native.Selector))
                .Throws<RoleFixtureJournal.StatusSucceededDeleteVaultCancellationHistoryException>();
        }
        finally { await File.WriteAllBytesAsync(f.Native.JournalPath, history); }
        await Assert.That(() => f.Source.RetryStatusSucceededDeleteVaultCancellationPersistence(f.Native.Selector))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Revision).IsEqualTo(state.Revision);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    private static async Task CompleteSucceededCancellation(PurgeServiceFixture f, ManagementOperation handle)
    {
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, handle, canceled.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, handle, default)).IsEqualTo(SecretStatus.Success);
    }

    private sealed record StatusSucceededCancellationReplayFrame(long Sequence, string Previous, RoleFixtureJournal.Snapshot State);
}
