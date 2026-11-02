using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using Collector = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationCollector;
using Provisioner = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureProvisioner;
using Trial = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultPolicyPermissionTrial;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments(false, false, false)]
    [Arguments(false, true, false)]
    [Arguments(true, false, true)]
    [Arguments(false, false, true)]
    public async Task NativeSetupPreservesSourceBaselineAndIndependentCanary(bool rbac, bool protectedVault, bool emptyPolicies)
    {
        using var f = new Fixture(rbac, protectedVault, emptyPolicies: emptyPolicies);
        var plan = f.Plan();
        using var material = SecretMaterial.FromText(Material);
        var result = await f.Source.ProvisionAsync(plan, material);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(VaultAdministrationEffects.SameConfiguration(result.Configuration!, f.Baseline)).IsTrue();
        await Assert.That(f.Wire.Vault!["properties"]!["enableRbacAuthorization"]!.GetValue<bool>()).IsEqualTo(rbac);
        await Assert.That(f.Wire.Vault!["properties"]!["enablePurgeProtection"]!.GetValue<bool>()).IsEqualTo(protectedVault);
        await Assert.That(f.Wire.Secret).IsEqualTo(Material);
        await Assert.That(result.CanaryVersion).IsEqualTo(Version);
        await Assert.That(result.CanarySha256).IsNotNull();
        await Assert.That(f.Wire.Prejournaled).IsTrue();
        await Assert.That(plan.Receipts.All(r => r.Terminated && r.NativeTask!.IsCompleted)).IsTrue();
        await Assert.That(f.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
        await Assert.That(f.Backends.Skip(2).SelectMany(b => b.Requests).All(r => r.Method == HttpMethod.Get)).IsTrue();
    }

    [Test]
    public async Task AbsentBaselineLeavesSelectedCreationToItsSource()
    {
        using var f = new Fixture();
        var plan = f.Plan(Provisioner.Preparation.Absent, seedCanary: false);
        var result = await f.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(result.VaultPresent).IsFalse();
        await Assert.That(result.DeletedVaultPresent).IsFalse();
        await Assert.That(f.Writes).IsEqualTo(0);
        await Assert.That(f.Read().Resources.All(r => !r.CreateAttempted)).IsTrue();
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Released);
    }

    [Test]
    public async Task DeletedPreparationKeepsSelectedRootOpenAndCanBeExplicitlyPurged()
    {
        using var f = new Fixture(allowPurge: true);
        var plan = f.Plan(Provisioner.Preparation.Deleted);
        using var material = SecretMaterial.FromText(Material);
        var ready = await f.Source.ProvisionAsync(plan, material);
        await Assert.That(ready.State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(ready.VaultPresent).IsFalse();
        await Assert.That(ready.DeletedVaultPresent).IsTrue();
        await Assert.That(f.Read().Closing).IsFalse();
        await Assert.That(f.Read().Resources.All(r => !r.SelectedAttempted)).IsTrue();
        await Assert.That(f.Read().Resources.Single(r => r.Id == plan.DeletedId).CreateAttempted).IsTrue();
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true)).State).IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Wire.Deleted).IsFalse();
        await Assert.That(f.Wire.Secret).IsNull();
    }

    [Test]
    [Arguments("deleted-protection")]
    [Arguments("deleted-retention")]
    public async Task DeletedPreparationRejectsSubstitutedProtectionAndRetention(string fault)
    {
        using var f = new Fixture();
        f.Wire.ReadFault = fault;
        var plan = f.Plan(Provisioner.Preparation.Deleted, seedCanary: false);
        var result = await f.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(f.Wire.Deleted).IsTrue();
        await Assert.That(f.Read().Released).IsFalse();
    }

    [Test]
    public async Task ProtectionIsNotRewrittenToMakeCleanupPossible()
    {
        using var f = new Fixture(protectedVault: true, allowPurge: true);
        var plan = f.Plan(seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        var result = await f.Source.ReleaseAsync(Owner, f.Selector, purge: true);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.SoftDeleted);
        await Assert.That(f.Read().Released).IsFalse();
        await Assert.That(f.Wire.Deleted).IsTrue();
        await Assert.That(f.Backends.SelectMany(b => b.Requests).Any(r => r.Method == HttpMethod.Post)).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PreexistingCoordinatesNeverBecomeOwnedByReadback(bool deleted)
    {
        using var f = new Fixture();
        var plan = f.Plan(seedCanary: false);
        f.Wire.Seed(plan, f.Baseline, f.Selector.Nonce);
        f.Wire.Active = !deleted;
        f.Wire.Deleted = deleted;
        await Assert.That((await f.Source.ProvisionAsync(plan)).State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(f.Writes).IsEqualTo(0);
        await Assert.That(f.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("tenant")]
    [Arguments("configuration")]
    [Arguments("partial")]
    [Arguments("numeric-permission")]
    public async Task IndependentSubstitutedReadCannotAdmitSetupOrCleanup(string fault)
    {
        using var f = new Fixture();
        var plan = f.Plan(seedCanary: false);
        f.Wire.ReadFault = fault;
        var result = await f.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(f.Wire.Secret).IsNull();
        await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(f.Backends.SelectMany(b => b.Requests).Any(r => r.Method == HttpMethod.Delete)).IsFalse();
        await Assert.That(f.Read().Released).IsFalse();
    }

    [Test]
    public async Task DeniedOrOversizedIndependentReadNeverStartsSetup()
    {
        foreach (string fault in new[] { "denied", "oversized" })
        {
            using var f = new Fixture();
            var plan = f.Plan(seedCanary: false);
            f.Wire.ReadFault = fault;
            await Assert.That((await f.Source.ProvisionAsync(plan)).State).IsNotEqualTo(Provisioner.State.Ready);
            await Assert.That(f.Writes).IsEqualTo(0);
            await Assert.That(f.Read().Resources.All(r => !r.CreateAttempted)).IsTrue();
        }
    }

    [Test]
    public async Task PendingNativeSetupNeedsExplicitStatusAndNeverReplays()
    {
        using var f = new Fixture();
        f.Wire.CreateFault = "async";
        var plan = f.Plan();
        using var material = SecretMaterial.FromText(Material);
        await Assert.That((await f.Source.ProvisionAsync(plan, material)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Wire.Secret).IsNull();
        int writes = f.Writes;
        await f.Source.ObserveAsync(Owner, f.Selector);
        await Assert.That(f.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.Writes).IsEqualTo(writes);
        await Assert.That(async () => await f.Source.ProvisionAsync(plan, material)).Throws<InvalidOperationException>();
        await Assert.That((await f.Source.SettleAsync(plan)).State).IsEqualTo(Provisioner.State.Pending);
        f.Wire.NativeStatus = "Succeeded";
        await Assert.That((await f.Source.SettleAsync(plan)).State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That((await f.Source.ContinueAsync(plan, material)).State).IsEqualTo(Provisioner.State.Ready);
        await f.Source.ContinueAsync(plan, material);
        await Assert.That(f.Backends[0].Requests.Count(r => r.Method == HttpMethod.Put)).IsEqualTo(1);
        await Assert.That(f.Backends[1].Requests.Count(r => r.Method == HttpMethod.Put && r.Authorized)).IsEqualTo(1);
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    [Arguments("202")]
    [Arguments("foreign-status")]
    public async Task UncertainSetupCannotBeSettledByRestartOrPresence(string fault)
    {
        using var f = new Fixture();
        f.Wire.CreateFault = fault;
        var plan = f.Plan(seedCanary: false);
        await Assert.That((await f.Source.ProvisionAsync(plan)).State).IsNotEqualTo(Provisioner.State.Ready);
        await Assert.That(f.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        var restarted = f.Reopen();
        await restarted.ObserveAsync(Owner, f.Selector);
        await restarted.SettleAsync(Owner, f.Selector);
        await Assert.That((await restarted.ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Writes).IsEqualTo(1);
        await Assert.That(f.Backends.SelectMany(b => b.Requests).All(r => r.Host is "management.azure.com")).IsTrue();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    [Arguments("async")]
    public async Task CanaryUncertaintyRetainsItsDispatchAndCannotBeReplayed(string fault)
    {
        using var f = new Fixture();
        f.Wire.SecretFault = fault;
        var plan = f.Plan();
        using var material = SecretMaterial.FromText(Material);
        await Assert.That((await f.Source.ProvisionAsync(plan, material)).State).IsNotEqualTo(Provisioner.State.Ready);
        await Assert.That(f.Read().Resources.Single(r => r.Id == plan.SecretId).ActiveDispatch).IsNotEqualTo(Guid.Empty);
        int writes = f.Writes;
        await f.Source.ContinueAsync(plan, material);
        await f.Source.SettleAsync(plan);
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Writes).IsEqualTo(writes);
        await Assert.That(plan.Receipts.All(r => r.Terminated && r.NativeTask!.IsCompleted)).IsTrue();
    }

    [Test]
    public async Task AsyncPurgeRequiresRetainedNativeStatusBeforeAbsenceCanRelease()
    {
        using var f = new Fixture(allowPurge: true);
        var plan = f.Plan(seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        f.Wire.PurgeFault = "async";
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Read().Released).IsFalse();
        await Assert.That((await f.Source.SettleAsync(plan)).State).IsEqualTo(Provisioner.State.Pending);
        f.Wire.NativeStatus = "Succeeded";
        await f.Source.SettleAsync(plan);
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true)).State).IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Backends[0].Requests.Count(r => r.Method == HttpMethod.Delete)).IsEqualTo(1);
        await Assert.That(f.Backends[0].Requests.Count(r => r.Method == HttpMethod.Post)).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Delete202CompletedSdkWrapperCannotEstablishRemoteSettlement(bool baselineDelete)
    {
        using var f = new Fixture(allowPurge: true);
        var plan = f.Plan(baselineDelete ? Provisioner.Preparation.Deleted : Provisioner.Preparation.Active, false);
        if (baselineDelete) f.Wire.DeleteFault = "async";
        var setup = await f.Source.ProvisionAsync(plan);
        if (!baselineDelete)
        {
            await Assert.That(setup.State).IsEqualTo(Provisioner.State.Ready);
            f.Wire.DeleteFault = "async";
        }
        else await Assert.That(setup.State).IsNotEqualTo(Provisioner.State.Ready);
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Pending);
        // The installed ARM SDK returns a completed wrapper even for this
        // unsupported 202 shape. Retain it, but do not treat it as settlement.
        var deletion = plan.Receipts.Single(r => r.Action is Provisioner.Action.DeleteVault or Provisioner.Action.PrepareDeletedVault);
        await Assert.That(deletion.NativeOperation).IsNotNull();
        await Assert.That(deletion.NativeOperation!.HasCompleted).IsTrue();
        await Assert.That(deletion.RemoteSettled).IsFalse();
        await Assert.That((await f.Source.SettleAsync(plan)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Wire.Active).IsFalse();
        await Assert.That(f.Wire.Deleted).IsTrue();
        await Assert.That(f.Backends[0].Requests.Count(r => r.Method == HttpMethod.Delete)).IsEqualTo(1);
        await Assert.That(f.Backends[0].Requests.Any(r => r.Method == HttpMethod.Post)).IsFalse();
        f.Wire.NativeStatus = "Succeeded";
        await Assert.That((await f.Source.SettleAsync(plan)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(deletion.RemoteSettled).IsFalse();
        await Assert.That(f.Backends[0].Requests.Any(r => r.Path.Contains("/operationResults/", StringComparison.Ordinal))).IsFalse();
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Backends[0].Requests.Count(r => r.Method == HttpMethod.Delete)).IsEqualTo(1);
    }

    [Test]
    [Arguments("delete")]
    [Arguments("purge")]
    public async Task LostCleanupDoesNotReplayEvenWhenIndependentStateIsAbsent(string action)
    {
        using var f = new Fixture(allowPurge: true);
        var plan = f.Plan(seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        if (action == "delete") f.Wire.DeleteFault = "lost";
        else f.Wire.PurgeFault = "lost";
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true)).State).IsEqualTo(Provisioner.State.Pending);
        int writes = f.Writes;
        await f.Reopen().SettleAsync(Owner, f.Selector);
        await Assert.That((await f.Reopen().ReleaseAsync(Owner, f.Selector, purge: true)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Writes).IsEqualTo(writes);
        await Assert.That(f.Read().Released).IsFalse();
    }

    [Test]
    public async Task AppliedBlockedTaskFencesCleanupUntilActualTermination()
    {
        using var f = new Fixture();
        f.Wire.Applied = Signal();
        f.Wire.Resume = Signal();
        var plan = f.Plan(seedCanary: false);
        using var stop = new CancellationTokenSource();
        var task = f.Source.ProvisionAsync(plan, cancellationToken: stop.Token).AsTask();
        await f.Wire.Applied.Task.WaitAsync(TimeSpan.FromSeconds(10));
        try
        {
            stop.Cancel();
            await Assert.That(plan.Receipts.Single().Terminated).IsFalse();
            await Assert.That(f.Read().Resources.Single(r => r.Id == plan.VaultId).ActiveDispatch).IsNotEqualTo(Guid.Empty);
            await Assert.That((await f.Reopen().ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Pending);
            await Assert.That(f.Backends[0].Requests.Any(r => r.Method == HttpMethod.Delete)).IsFalse();
        }
        finally { f.Wire.Resume.TrySetResult(); }
        await Assert.That(async () => await task).Throws<OperationCanceledException>();
        await Assert.That(plan.Receipts.Single().Terminated).IsTrue();
        await Assert.That((await f.Reopen().ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Pending);
    }

    [Test]
    public async Task JournalContentionRetainsCompletionForFinalizationWithoutNativeReplay()
    {
        using var f = new Fixture();
        f.Wire.Applied = Signal();
        f.Wire.Resume = Signal();
        var plan = f.Plan(seedCanary: false);
        var task = f.Source.ProvisionAsync(plan).AsTask();
        await f.Wire.Applied.Task.WaitAsync(TimeSpan.FromSeconds(10));
        using (var locked = new FileStream(f.JournalPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            f.Wire.Resume.TrySetResult();
            await Assert.That(async () => await task).Throws<InvalidOperationException>();
            await Assert.That(plan.Receipts.Single().Terminated).IsTrue();
            await Assert.That(plan.Receipts.Single().RemoteSettled).IsTrue();
        }
        await Assert.That((await f.Source.SettleAsync(plan)).State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That((await f.Source.ContinueAsync(plan)).State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(f.Backends[0].Requests.Count(r => r.Method == HttpMethod.Put)).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PositiveReadInvalidatesStaleAbsenceAndRepeatedAbsenceIsIdempotent(bool partial)
    {
        using var f = new Fixture();
        var plan = f.Plan(Provisioner.Preparation.Absent, seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        await f.Source.ReleaseAsync(Owner, f.Selector);
        long length = new FileInfo(f.JournalPath).Length;
        await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(new FileInfo(f.JournalPath).Length).IsEqualTo(length);
        f.Wire.Seed(plan, f.Baseline, Guid.NewGuid());
        if (partial) f.Wire.ReadFault = "partial";
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(f.Read().Released).IsFalse();
        await Assert.That(f.Read().Resources.Single(r => r.Id == plan.VaultId).Absent).IsFalse();
        await Assert.That(f.Writes).IsEqualTo(0);
    }

    [Test]
    public async Task ExplicitBorrowedRowsAreNeverMutationAuthority()
    {
        using var f = new Fixture();
        string[] borrowed = Enumerable.Range(0, 13).Select(i => Group + "/providers/Microsoft.Network/privateEndpoints/borrowed" + i).ToArray();
        var plan = f.Plan(Provisioner.Preparation.Absent, false, borrowed);
        await f.Source.ProvisionAsync(plan);
        await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(f.Read().Resources.Length).IsEqualTo(16);
        await Assert.That(f.Read().Resources.Count(r => r.Borrowed)).IsEqualTo(13);
        await Assert.That(f.Backends.SelectMany(b => b.Requests).Any(r => borrowed.Contains(r.Path))).IsFalse();
        await Assert.That(f.Read().Released).IsTrue();
    }

    [Test]
    public async Task PreCancellationAndCloseBeforePrepareSendNothing()
    {
        using var f = new Fixture();
        var plan = f.Plan(seedCanary: false);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.ProvisionAsync(plan, cancellationToken: stop.Token)).Throws<OperationCanceledException>();
        await Assert.That(async () => await f.Source.ObserveAsync(Owner, f.Selector, stop.Token)).Throws<OperationCanceledException>();
        await Assert.That(async () => await f.Source.SettleAsync(plan, stop.Token)).Throws<OperationCanceledException>();
        await Assert.That(async () => await f.Source.ReleaseAsync(Owner, f.Selector, cancellationToken: stop.Token)).Throws<OperationCanceledException>();
        await Assert.That(f.Backends.SelectMany(b => b.Requests).Any()).IsFalse();
        await Assert.That(f.Read().Resources.All(r => !r.CreateAttempted)).IsTrue();
        await Assert.That(f.Read().Closing).IsFalse();
        using var other = new Fixture();
        other.Source.CloseSelectedRoot(Owner, other.Selector);
        await Assert.That(() => other.Plan()).Throws<InvalidOperationException>();
        await Assert.That(other.Writes).IsEqualTo(0);
    }

    [Test]
    public async Task InvalidBaselinesAndBorrowedScopesAreRejectedBeforeSending()
    {
        using var f = new Fixture();
        foreach (var invalid in new[]
        {
            f.Baseline with { Sku = (VaultSku)99 },
            f.Baseline with { TenantId = Guid.NewGuid() },
            f.Baseline with { Location = "other-location" },
            f.Baseline with { Policies = [new(Tenant, Principal, [(SecretPermission)99], null)] },
            f.Baseline with { RetentionDays = 1 }
        })
            await Assert.That(() => f.Reopen(invalid)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Plan(borrowed: ["/subscriptions/" + Guid.NewGuid() + "/resourceGroups/foreign"]))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Plan(borrowed: Enumerable.Range(0, 14).Select(i => Group + "/providers/Microsoft.Network/privateEndpoints/b" + i).ToArray()))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Writes).IsEqualTo(0);
    }

    [Test]
    public async Task DeniedSecretReadAndProtectedDiagnosticsCannotProduceReadiness()
    {
        using var f = new Fixture();
        f.Wire.SecretReadDenied = true;
        var plan = f.Plan();
        using var material = SecretMaterial.FromText(Material);
        var result = await f.Source.ProvisionAsync(plan, material);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Denied);
        string output = string.Join("|", f.Source, plan, result, plan.Receipts[0],
            JsonSerializer.Serialize(plan), JsonSerializer.Serialize(result), JsonSerializer.Serialize(plan.Receipts));
        foreach (string protectedText in new[] { Material, Subscription.ToString(), plan.VaultName, "protected-native-message" })
            await Assert.That(output.Contains(protectedText, StringComparison.Ordinal)).IsFalse();
        await Assert.That(f.Backends.All(b => !b.Disposed)).IsTrue();
    }

    [Test]
    public async Task CallerMutationCannotChangeCapturedBaselinePolicies()
    {
        using var f = new Fixture();
        f.Baseline.Policies[0].Permissions[0] = SecretPermission.Purge;
        var plan = f.Plan(seedCanary: false);
        var result = await f.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(result.Configuration!.Policies[0].Permissions.Contains(SecretPermission.Get)).IsTrue();
        await Assert.That(result.Configuration!.Policies[0].Permissions.Contains(SecretPermission.Purge)).IsFalse();
    }

    [Test]
    public async Task RestartNeverReconstructsSuccessfulPreparationFromCoordinatesAlone()
    {
        using var f = new Fixture();
        var plan = f.Plan(seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        var observed = await f.Reopen().ObserveAsync(Owner, f.Selector);
        await Assert.That(observed.State).IsEqualTo(Provisioner.State.Incomplete);
        await Assert.That(observed.VaultPresent).IsTrue();
        await Assert.That(f.Writes).IsEqualTo(1);
    }

    [Test]
    public async Task OversizedNativeCanaryRequestIsRejectedBeforeItsDispatch()
    {
        using var f = new Fixture(maximumBytes: 2048);
        var plan = f.Plan();
        using var material = SecretMaterial.FromText(new string('x', 4096));
        var result = await f.Source.ProvisionAsync(plan, material);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(f.Wire.Active).IsTrue();
        await Assert.That(f.Wire.Secret).IsNull();
        await Assert.That(f.Read().Resources.Single(r => r.Id == plan.SecretId).CreateAttempted).IsFalse();
        await Assert.That(f.Backends[1].Requests.Any()).IsFalse();
    }

    [Test]
    [Arguments("Active")]
    [Arguments("Deleted")]
    [Arguments("Absent")]
    public async Task DeclaredPolicyChildrenUseNativeOwnedHistory(string desiredState)
    {
        var desired = Enum.Parse<Provisioner.Preparation>(desiredState);
        using var f = new Fixture(allowPurge: true);
        using var input = SecretMaterial.FromText(Material);
        var plan = f.Plan(seedCanary: false, children: [new("policy-child", desired, input, RetainBackup: true)]);
        input.Dispose();
        var result = await f.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Ready);
        var child = plan.PolicyChildren.Single();
        await Assert.That(child.Prepared).IsTrue();
        await Assert.That(child.Version).IsEqualTo(Version);
        await Assert.That(child.Sha256).IsNotNull();
        using var backup = child.CopyBackup();
        byte[] bytes = backup!.Export();
        try
        {
            await Assert.That(Encoding.UTF8.GetString(bytes)).IsEqualTo("native:policy-child:" + Version + ":" + Material);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
        using var material = child.CopySet();
        await Assert.That(material.Reveal()).IsEqualTo(Material);
        await Assert.That(f.Wire.Children.ContainsKey(child.Name)).IsEqualTo(desired == Provisioner.Preparation.Active);
        await Assert.That(f.Wire.DeletedChildren.ContainsKey(child.Name)).IsEqualTo(desired == Provisioner.Preparation.Deleted);
        await Assert.That(f.Wire.Prejournaled).IsTrue();
        await Assert.That(f.Read().Resources.All(r => !r.SelectedAttempted && r.ActiveDispatch == Guid.Empty)).IsTrue();
        await Assert.That(f.Read().Resources.Single(r => r.Id.EndsWith("/secrets/policy-child", StringComparison.Ordinal)).CreateAttempted).IsTrue();
        await Assert.That(plan.Receipts.All(r => r.Terminated && r.NativeTask!.IsCompleted)).IsTrue();
    }

    [Test]
    [Arguments(11, false)]
    [Arguments(21, false)]
    [Arguments(21, true)]
    public async Task BoundedChildrenFitOriginalDeclarationAndNativeCleanup(int count, bool restart)
    {
        using var f = new Fixture(allowPurge: true);
        using var material = SecretMaterial.FromText(Material);
        var specifications = Enumerable.Range(0, count).Select(i =>
            new Provisioner.PolicyChildSpecification("policy-" + i, Provisioner.Preparation.Active, material)).ToArray();
        var plan = f.Plan(children: specifications);
        await Assert.That(f.Read().Resources.Length).IsEqualTo(count + 3);
        specifications[0] = new("substituted", Provisioner.Preparation.Deleted, material);
        await Assert.That((await f.Source.ProvisionAsync(plan, material)).State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(plan.PolicyChildren[0].Name).IsEqualTo("policy-0");
        await Assert.That(f.Wire.Children.Count).IsEqualTo(count);
        await Assert.That(plan.PolicyChildren.All(c => c.Prepared && c.Version == Version && c.Sha256 is not null)).IsTrue();
        await Assert.That(f.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty && !r.SelectedAttempted)).IsTrue();
        await using var cleanup = f.Reopen();
        await Assert.That((await (restart ? cleanup : f.Source).ReleaseAsync(Owner, f.Selector, purge: true)).State)
            .IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Read().Resources.Where(r => !r.Borrowed).All(r => r.Absent)).IsTrue();
        await Assert.That(f.Wire.Children.Count + f.Wire.DeletedChildren.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments(8)]
    [Arguments(9)]
    public async Task BorrowedCoordinatesShareTheTwentyOneChildBudget(int children)
    {
        using var f = new Fixture();
        using var material = SecretMaterial.FromText(Material);
        var specifications = Enumerable.Range(0, children).Select(i =>
            new Provisioner.PolicyChildSpecification("policy-" + i, Provisioner.Preparation.Active, material)).ToArray();
        string[] borrowed = Enumerable.Range(0, 13)
            .Select(i => Group + "/providers/Microsoft.Network/privateEndpoints/borrowed" + i).ToArray();
        if (children == 9)
        {
            await Assert.That(() => f.Plan(borrowed: borrowed, children: specifications)).Throws<InvalidOperationException>();
            await Assert.That(File.Exists(f.JournalPath)).IsFalse();
        }
        else
        {
            var plan = f.Plan(borrowed: borrowed, children: specifications);
            await Assert.That(plan.PolicyChildren.Count).IsEqualTo(8);
            await Assert.That(f.Read().Resources.Length).IsEqualTo(24);
            await Assert.That(f.Read().Resources.Count(r => r.Borrowed)).IsEqualTo(13);
        }
        await Assert.That(f.Writes).IsEqualTo(0);
    }

    [Test]
    [Arguments("name")]
    [Arguments("canary")]
    [Arguments("duplicate")]
    [Arguments("rows")]
    [Arguments("purge")]
    [Arguments("protection")]
    [Arguments("inactive")]
    public async Task InvalidChildDeclarationsNeverPrepareOrSend(string fault)
    {
        using var f = new Fixture(protectedVault: fault == "protection", allowPurge: fault != "purge");
        using var material = SecretMaterial.FromText(Material);
        var spec = new Provisioner.PolicyChildSpecification(
            fault == "name" ? "../foreign" : fault == "canary" ? "CANARY" : "policy-child",
            fault is "purge" or "protection" ? Provisioner.Preparation.Absent : Provisioner.Preparation.Active, material);
        Provisioner.PolicyChildSpecification[] specs = fault == "duplicate" ? new[] { spec, spec } :
            fault == "rows" ? Enumerable.Range(0, 22).Select(i => spec with { Name = "policy-" + i }).ToArray() : [spec];
        await Assert.That(() => f.Plan(fault == "inactive" ? Provisioner.Preparation.Deleted : Provisioner.Preparation.Active,
            seedCanary: false, children: specs)).Throws<InvalidOperationException>();
        await Assert.That(File.Exists(f.JournalPath)).IsFalse();
        await Assert.That(f.Writes).IsEqualTo(0);
    }

    [Test]
    [Arguments("set")]
    [Arguments("backup")]
    [Arguments("delete")]
    [Arguments("purge")]
    [Arguments("observe")]
    public async Task EachUncertainChildStepRetainsOriginalFenceAndNeverReplays(string step)
    {
        using var f = new Fixture(allowPurge: true);
        using var material = SecretMaterial.FromText(Material);
        f.Wire.ChildFaultStep = step;
        var plan = f.Plan(seedCanary: false,
            children: [new("policy-child", Provisioner.Preparation.Absent, material, RetainBackup: true)]);
        await Assert.That((await f.Source.ProvisionAsync(plan)).State).IsNotEqualTo(Provisioner.State.Ready);
        int writes = f.Writes;
        await Assert.That(plan.PolicyChildren.Single().Prepared).IsFalse();
        await Assert.That(f.Read().Resources.Single(r => r.Id.EndsWith("/secrets/policy-child", StringComparison.Ordinal)).ActiveDispatch)
            .IsNotEqualTo(Guid.Empty);
        await f.Source.ContinueAsync(plan);
        await f.Reopen().SettleAsync(Owner, f.Selector);
        await Assert.That((await f.Reopen().ReleaseAsync(Owner, f.Selector, purge: true)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Writes).IsEqualTo(writes);
        await Assert.That(f.Read().Resources.All(r => !r.SelectedAttempted)).IsTrue();
    }

    [Test]
    [Arguments("foreign")]
    [Arguments("wrong-value")]
    [Arguments("202")]
    [Arguments("backup")]
    public async Task ChildRawReplyCannotSubstituteIdentityMaterialOrSettlement(string fault)
    {
        using var f = new Fixture(allowPurge: true);
        using var material = SecretMaterial.FromText(Material);
        f.Wire.ChildReplyFault = fault;
        var plan = f.Plan(seedCanary: false,
            children: [new("policy-child", Provisioner.Preparation.Absent, material, RetainBackup: true)]);
        await Assert.That((await f.Source.ProvisionAsync(plan)).State).IsNotEqualTo(Provisioner.State.Ready);
        await Assert.That(plan.PolicyChildren.Single().Prepared).IsFalse();
        await Assert.That(f.Wire.DeletedChildren.Count).IsEqualTo(0);
        await Assert.That(f.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    [Arguments("oversized")]
    [Arguments("duplicate")]
    [Arguments("headers")]
    [Arguments("length")]
    [Arguments("recovery")]
    [Arguments("version")]
    public async Task BoundedChildRepliesCannotManufacturePreparedState(string fault)
    {
        using var f = new Fixture(allowPurge: true);
        using var material = SecretMaterial.FromText(Material);
        var plan = f.Plan(seedCanary: false,
            children: [new("policy-child", Provisioner.Preparation.Absent, material, RetainBackup: true)]);
        f.Wire.ChildReplyFault = fault;
        await Assert.That((await f.Source.ProvisionAsync(plan)).State).IsNotEqualTo(Provisioner.State.Ready);
        await Assert.That(plan.PolicyChildren.Single().Prepared).IsFalse();
        await Assert.That(f.Backends[1].Requests.Any(r => r.Path.StartsWith("/deletedsecrets/", StringComparison.Ordinal))).IsFalse();
        await Assert.That(f.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    public async Task RestartUsesDeclaredCoordinatesButCannotInventPreparedMaterial()
    {
        using var f = new Fixture(allowPurge: true);
        using var material = SecretMaterial.FromText(Material);
        var plan = f.Plan(seedCanary: false,
            children: [new("policy-child", Provisioner.Preparation.Absent, material, RetainBackup: true)]);
        await Assert.That((await f.Source.ProvisionAsync(plan)).State).IsEqualTo(Provisioner.State.Ready);
        var reopened = f.Reopen();
        await Assert.That((await reopened.ObserveAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Incomplete);
        await Assert.That((await reopened.ReleaseAsync(Owner, f.Selector, purge: true)).State).IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Read().Resources.All(r => r.Absent || r.Borrowed)).IsTrue();
    }

    [Test]
    public async Task ChildTaskAndSourceDisposalJoinActualBorrowerBeforeZeroing()
    {
        using var f = new Fixture();
        using var material = SecretMaterial.FromText(Material);
        var plan = f.Plan(seedCanary: false, children: [new("policy-child", Provisioner.Preparation.Active, material)]);
        f.Wire.ChildApplied = Signal();
        f.Wire.ChildResume = Signal();
        using var stop = new CancellationTokenSource();
        var actual = f.Source.ProvisionAsync(plan, cancellationToken: stop.Token).AsTask();
        await f.Wire.ChildApplied.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var disposal = f.Source.DisposeAsync().AsTask();
        try
        {
            stop.Cancel();
            await Assert.That(disposal.IsCompleted).IsFalse();
            await Assert.That(plan.Receipts.Last().Terminated).IsFalse();
            using var retained = plan.PolicyChildren.Single().CopySet();
            await Assert.That(retained.Reveal()).IsEqualTo(Material);
            await Assert.That((await f.Reopen().ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Pending);
        }
        finally { f.Wire.ChildResume.TrySetResult(); }
        await Assert.That(async () => await actual).Throws<OperationCanceledException>();
        await disposal;
        await Assert.That(() => plan.PolicyChildren.Single().CopySet()).Throws<ObjectDisposedException>();
        await Assert.That(f.Backends.All(b => !b.Disposed)).IsTrue();
    }

    [Test]
    [Arguments("set")]
    [Arguments("backup")]
    [Arguments("delete")]
    public async Task CloseBetweenChildStepsPreventsEveryLaterSetupDispatch(string step)
    {
        using var f = new Fixture(allowPurge: true);
        using var material = SecretMaterial.FromText(Material);
        var plan = f.Plan(seedCanary: false,
            children: [new("policy-child", Provisioner.Preparation.Absent, material, RetainBackup: true)]);
        f.Wire.ChildAfterStep = completed =>
        {
            if (completed == step) f.Source.CloseSelectedRoot(Owner, f.Selector);
        };
        await Assert.That((await f.Source.ProvisionAsync(plan)).State).IsNotEqualTo(Provisioner.State.Ready);
        await Assert.That(f.Read().Closing).IsTrue();
        await Assert.That(plan.PolicyChildren.Single().Prepared).IsFalse();
        var requests = f.Backends[1].Requests.Where(r => r.Path.Contains("policy-child", StringComparison.Ordinal)).ToArray();
        await Assert.That(requests.Any(r => r.Method == HttpMethod.Put)).IsTrue();
        await Assert.That(requests.Any(r => r.Path.EndsWith("/backup", StringComparison.Ordinal))).IsEqualTo(step != "set");
        await Assert.That(requests.Any(r => r.Method == HttpMethod.Delete && r.Path.StartsWith("/secrets/", StringComparison.Ordinal)))
            .IsEqualTo(step == "delete");
        await Assert.That(requests.Any(r => r.Path.StartsWith("/deletedsecrets/", StringComparison.Ordinal))).IsFalse();
        await Assert.That((await f.Reopen().ReleaseAsync(Owner, f.Selector, purge: true)).State).IsEqualTo(Provisioner.State.Pending);
    }

    [Test]
    public async Task UnknownPreexistingChildHistoryIsNeverOverwritten()
    {
        using var f = new Fixture();
        using var material = SecretMaterial.FromText(Material);
        var plan = f.Plan(seedCanary: false, children: [new("policy-child", Provisioner.Preparation.Active, material)]);
        f.Wire.Children.Add("policy-child", "unknown-owned-by-someone-else");
        await Assert.That((await f.Source.ProvisionAsync(plan)).State).IsNotEqualTo(Provisioner.State.Ready);
        await Assert.That(f.Wire.Children["policy-child"]).IsEqualTo("unknown-owned-by-someone-else");
        await Assert.That(f.Backends[1].Requests.Count).IsEqualTo(0);
        await Assert.That(plan.PolicyChildren.Single().Prepared).IsFalse();
    }

    [Test]
    [Arguments("root")]
    [Arguments("name")]
    [Arguments("borrowed")]
    [Arguments("foreign")]
    public async Task ReconstructionRejectsInvalidDurableChildDeclarations(string fault)
    {
        using var f = new Fixture();
        string vault = Group + "/providers/Microsoft.KeyVault/vaults/skv" + new string('a', 21);
        string deleted = $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/skv" + new string('a', 21);
        string child = fault == "foreign" ? Group + "/providers/Microsoft.KeyVault/vaults/foreign/secrets/policy-child" :
            vault + "/secrets/" + (fault == "name" ? "illegal_name" : "policy-child");
        f.Journal.Prepare(Owner, f.Selector,
        [
            new(fault == "root" ? vault.Replace(Subscription.ToString(), Guid.NewGuid().ToString(), StringComparison.Ordinal) : vault, false),
            new(vault + "/secrets/canary", false, CleanupOnly: true),
            new(deleted, false, CleanupOnly: true),
            new(child, fault == "borrowed")
        ]);
        await Assert.That(async () => await f.Source.ObserveAsync(Owner, f.Selector)).Throws<InvalidOperationException>();
        await Assert.That(f.Backends.SelectMany(b => b.Requests).Any()).IsFalse();
    }

    [Test]
    public async Task SoftDeletedParentRetainsChildrenUntilBothNativeVaultFormsAreAbsent()
    {
        using var f = new Fixture(allowPurge: true);
        using var material = SecretMaterial.FromText(Material);
        var plan = f.Plan(seedCanary: false, children: [new("policy-child", Provisioner.Preparation.Active, material)]);
        await f.Source.ProvisionAsync(plan);
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.SoftDeleted);
        await Assert.That(f.Read().Resources.Single(r => r.Id.EndsWith("/secrets/policy-child", StringComparison.Ordinal)).Absent).IsFalse();
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true)).State).IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Read().Resources.Single(r => r.Id.EndsWith("/secrets/policy-child", StringComparison.Ordinal)).Absent).IsTrue();
    }

    [Test]
    public async Task DisposingSourceClearsOwnedSnapshotsButNotExportedHostCopies()
    {
        using var f = new Fixture(allowPurge: true);
        using var material = SecretMaterial.FromText(Material);
        var plan = f.Plan(seedCanary: false,
            children: [new("policy-child", Provisioner.Preparation.Absent, material, RetainBackup: true)]);
        await f.Source.ProvisionAsync(plan);
        var child = plan.PolicyChildren.Single();
        using var exportedSet = child.CopySet();
        using var exportedBackup = child.CopyBackup();
        var fields = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;
        char[] set = (char[])typeof(Provisioner.PolicyChild).GetField("set", fields)!.GetValue(child)!;
        byte[] backup = (byte[])typeof(Provisioner.PolicyChild).GetField("backup", fields)!.GetValue(child)!;
        await f.Source.DisposeAsync();
        await Assert.That(set.All(c => c == '\0') && backup.All(b => b == 0)).IsTrue();
        await Assert.That(exportedSet.Reveal()).IsEqualTo(Material);
        byte[] copy = exportedBackup!.Export();
        try { await Assert.That(copy.Any(b => b != 0)).IsTrue(); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(copy); }
        await Assert.That(() => child.CopyBackup()).Throws<ObjectDisposedException>();
        await Assert.That(() => f.Source.PlanFixture(Owner, f.Selector with { Nonce = Guid.NewGuid() },
            Provisioner.Preparation.Active, [], seedCanary: false)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ChildLateBodyIsJoinedAcrossCancellationAndSourceDisposal()
    {
        using var f = new Fixture();
        using var material = SecretMaterial.FromText(Material);
        var plan = f.Plan(seedCanary: false, children: [new("policy-child", Provisioner.Preparation.Active, material)]);
        f.Wire.ChildBodyEntered = Signal();
        f.Wire.ChildBodyResume = Signal();
        using var stop = new CancellationTokenSource();
        var actual = f.Source.ProvisionAsync(plan, cancellationToken: stop.Token).AsTask();
        await f.Wire.ChildBodyEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var disposal = f.Source.DisposeAsync().AsTask();
        try
        {
            stop.Cancel();
            await Assert.That(actual.IsCompleted || disposal.IsCompleted).IsFalse();
            await Assert.That(plan.Receipts.Last().Terminated).IsFalse();
            await Assert.That(f.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty && !r.InvocationTerminated)).IsTrue();
        }
        finally { f.Wire.ChildBodyResume.TrySetResult(); }
        await Assert.That(async () => await actual).Throws<OperationCanceledException>();
        await disposal;
        await Assert.That(plan.Receipts.Last().Terminated).IsTrue();
        await Assert.That(f.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    public async Task NativePreparedChildrenComposeSixteenSameVaultEffectsAndReleaseOriginalRoot()
    {
        using var f = new Fixture(allowPurge: true, emptyPolicies: true, policyWitness: true);
        using var material = SecretMaterial.FromText(Material);
        var specifications = new List<Provisioner.PolicyChildSpecification>
        {
            new("shared-read", Provisioner.Preparation.Active, material)
        };
        foreach (var permission in new[] { SecretPermission.Set, SecretPermission.Delete, SecretPermission.Recover,
            SecretPermission.Restore, SecretPermission.Purge })
            foreach (bool denied in new[] { true, false })
                specifications.Add(new(permission.ToString().ToLowerInvariant() + (denied ? "-denied" : "-intended"),
                    permission == SecretPermission.Delete ? Provisioner.Preparation.Active :
                    permission is SecretPermission.Recover or SecretPermission.Purge ? Provisioner.Preparation.Deleted :
                    Provisioner.Preparation.Absent, material, permission == SecretPermission.Restore));
        var plan = f.Plan(children: specifications.ToArray());
        var prepared = await f.Source.ProvisionAsync(plan, material);
        await Assert.That(prepared.State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(plan.PolicyChildren.All(c => c.Prepared)).IsTrue();
        var binding = new Collector.Binding(f.Selector, plan.LeaseId, Collector.QueryKind.ChangeAccessPolicies,
            Collector.ReadKind.GetVault, Subscription, "fixture-group", "eastus", plan.VaultName, null);
        var entries = new List<Trial.PreparedFixture>();
        try
        {
            foreach (var permission in Enum.GetValues<SecretPermission>())
                foreach (bool denied in new[] { true, false })
                {
                    bool read = permission is SecretPermission.Get or SecretPermission.List or SecretPermission.Backup;
                    string name = read ? "shared-read" :
                        permission.ToString().ToLowerInvariant() + (denied ? "-denied" : "-intended");
                    var child = plan.PolicyChildren.Single(c => c.Name == name);
                    entries.Add(new(permission, denied, name, permission == SecretPermission.Set ? null : child.Version,
                        child.Desired == Provisioner.Preparation.Active ? Trial.PreparedState.Active :
                        child.Desired == Provisioner.Preparation.Deleted ? Trial.PreparedState.Deleted : Trial.PreparedState.Absent,
                        child.Sha256!, permission == SecretPermission.Set ? child.CopySet() : null,
                        permission == SecretPermission.Restore ? child.CopyBackup() : null));
                }
            using var intendedClient = new HttpClient(new Backend("intended-secret", f.Wire));
            using var deniedClient = new HttpClient(new Backend("denied-secret", f.Wire));
            using var observerClient = new HttpClient(new Backend("read-secret", f.Wire));
            var claim = new Trial.PrincipalClaim(Tenant, Principal, null);
            await using var trial = new Trial(f.Journal, claim,
                new("intended", new Credential("intended-secret"), new HttpClientTransport(intendedClient)),
                new("denied", new Credential("denied-secret"), new HttpClientTransport(deniedClient)),
                new(65536, 4096, 65536, 2048, 64, 12, TimeSpan.FromSeconds(20)), TimeProvider.System,
                new("observer", new Credential("read-secret"), new HttpClientTransport(observerClient)));
            var window = trial.Arm(new(Owner, binding, Trial.Revision, entries.ToArray(), ["canary"]));
            var result = await trial.CollectAsync(window, binding);
            await Assert.That(result.Observations.Count).IsEqualTo(16);
            await Assert.That(result.Observations.All(o => o.Attempted && o.RemoteSettled)).IsTrue();
            await Assert.That(f.Wire.Prejournaled).IsTrue();
            var effects = trial.ComposePolicyEffects(window, binding, claim, result);
            var requested = new VaultAdministrationEffects.Policy(Tenant, Principal, Enum.GetValues<SecretPermission>(), null);
            var lease = new VaultAdministrationEffects.Lease(
                new(f.Selector.Nonce, plan.LeaseId, "source", "https://management.azure.com", "2026-02-01",
                    DateTimeOffset.UtcNow, [plan.VaultId]), plan.VaultName, null, "canary", prepared.CanarySha256!,
                f.Baseline, PrivateConnectionState.Unknown);
            var measured = new VaultAdministrationEffects.Measurement(plan.LeaseId, f.Selector.Nonce, "source",
                DateTimeOffset.UtcNow, plan.VaultId, SecretStatus.Success, SecretStatus.Absent, f.Baseline,
                [requested], PrivateConnectionState.Unknown, SecretStatus.Absent, effects, null, [], [], [], [], null);
            VaultAdministrationEffects.ValidateEffect("ChangeAccessPoliciesAsync", "change.Add", f.Baseline,
                lease, measured, [requested], AccessPolicyChange.Add, unchanged: false);
            await Assert.That(f.Read().Resources.Length).IsEqualTo(14);
            await Assert.That(f.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
            await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true)).State)
                .IsEqualTo(Provisioner.State.Released);
        }
        finally
        {
            foreach (var entry in entries) { entry.OwnedSet?.Dispose(); entry.Backup?.Dispose(); }
        }
    }

    private const string Owner = "source-owner";
    private const string Material = "controlled-private-canary";
    private const string Version = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static readonly Guid Subscription = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Tenant = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid Principal = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static string Group => $"/subscriptions/{Subscription:D}/resourceGroups/fixture-group";
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "vault-source-" + Guid.NewGuid().ToString("N"));
        private readonly HttpClient[] clients;
        private readonly HttpClientTransport[] transports;
        private readonly Credential[] credentials;
        private readonly bool allowPurge;
        private readonly int maximumBytes;
        internal FixtureSelector Selector = new(Guid.NewGuid(), "controlled",
            "a.management.VaultAdministration.CreateOrUpdateVaultAsync", "sku.Premium", "selected-contract");
        internal readonly VaultAdministrationEffects.Configuration Baseline;
        internal readonly WireState Wire = new();
        internal readonly Backend[] Backends;
        internal readonly RoleFixtureJournal Journal;
        internal readonly Provisioner Source;
        internal string JournalPath => Path.Combine(directory, Selector.Nonce.ToString("N") + ".journal");
        internal int Writes => Backends.SelectMany(b => b.Requests).Count(r => r.Method != HttpMethod.Get && r.Authorized);

        internal Fixture(bool rbac = false, bool protectedVault = false, bool allowPurge = false,
            bool emptyPolicies = false, int maximumBytes = 64 * 1024, bool policyWitness = false,
            bool policyRemoval = false, bool policyReplacement = false)
        {
            if (policyWitness) Selector = Selector with
            {
                Operation = Collector.Operation(Collector.QueryKind.ChangeAccessPolicies),
                Variant = policyRemoval ? "change.Remove" : policyReplacement ? "change.Replace" : "change.Add"
            };
            this.allowPurge = allowPurge;
            this.maximumBytes = maximumBytes;
            Baseline = new("eastus", Tenant, VaultSku.Premium, rbac, protectedVault, 23, false,
                policyRemoval ? [new(Tenant, Principal, Enum.GetValues<SecretPermission>(), null)] :
                policyReplacement ? [new(Tenant, Principal, [SecretPermission.Get], null)] :
                emptyPolicies ? [] : [new(Tenant, Principal, [SecretPermission.Get, SecretPermission.Set], null)]);
            Directory.CreateDirectory(directory);
            Journal = new(directory);
            Backends = new[] { "setup-arm", "setup-secret", "read-arm", "read-secret" }.Select(r => new Backend(r, Wire)).ToArray();
            credentials = Backends.Select(b => new Credential(b.Role)).ToArray();
            clients = Backends.Select(b => new HttpClient(b)).ToArray();
            transports = clients.Select(c => new HttpClientTransport(c)).ToArray();
            Wire.BeforeMutation = path =>
            {
                var rows = Read().Resources;
                string id = path.StartsWith("/secrets/", StringComparison.Ordinal) ||
                    path.StartsWith("/deletedsecrets/", StringComparison.Ordinal)
                    ? Wire.VaultId + "/secrets/" + path.Split('/')[2] :
                    path.EndsWith("/purge", StringComparison.Ordinal) ? path[..^6] : path;
                Wire.Prejournaled &= rows.Any(r => !r.Borrowed && r.ActiveDispatch != Guid.Empty &&
                    (r.Id == id || path == Wire.VaultId && r.Id.Contains("/deletedVaults/", StringComparison.Ordinal)));
            };
            Source = Reopen();
        }
        internal Provisioner Reopen(VaultAdministrationEffects.Configuration? baseline = null, TimeProvider? time = null) => new(new RoleFixtureJournal(directory),
            new(Subscription, "fixture-group", "eastus", Tenant, true, allowPurge), baseline ?? Baseline,
            new("setup-arm", credentials[0], transports[0]), new("setup-secret", credentials[1], transports[1]),
            new("read-arm", credentials[2], transports[2]), new("read-secret", credentials[3], transports[3]),
            new(maximumBytes, TimeSpan.FromSeconds(10)), time);
        internal Provisioner.Plan Plan(Provisioner.Preparation preparation = Provisioner.Preparation.Active,
            bool seedCanary = true, string[]? borrowed = null, Provisioner.PolicyChildSpecification[]? children = null,
            string[]? notifications = null, Provisioner.PrivateEndpointSpecification? privateEndpoint = null)
        {
            var plan = Source.PlanFixture(Owner, Selector, preparation, borrowed ?? [], seedCanary, children, notifications, privateEndpoint);
            Wire.VaultId = plan.VaultId;
            Wire.VaultName = plan.VaultName;
            return plan;
        }
        internal Provisioner Cleanup(string resourceGroup = "fixture-group") =>
            Provisioner.ForCleanup(new RoleFixtureJournal(directory),
                new(Subscription, resourceGroup, "eastus", Tenant, true, allowPurge),
                new("setup-arm", credentials[0], transports[0]), new("read-arm", credentials[2], transports[2]),
                new(maximumBytes, TimeSpan.FromSeconds(10)));
        internal void BeforeSetupCredential(Action action) => credentials[0].BeforeToken = action;
        internal RoleFixtureJournal.Snapshot Read() => Journal.Read(Owner, Selector);
        public void Dispose()
        {
            try { Source.DisposeAsync().AsTask().GetAwaiter().GetResult(); }
            finally
            {
                foreach (var client in clients) client.Dispose();
                Directory.Delete(directory, true);
            }
        }
    }

    private sealed class Credential(string role) : TokenCredential
    {
        internal Action? BeforeToken;
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string audience = role.EndsWith("arm", StringComparison.Ordinal) ? "https://management.azure.com/.default" : "https://vault.azure.net/.default";
            if (context.Scopes.Length != 1 || context.Scopes[0] != audience) throw new InvalidOperationException("controlled-audience");
            BeforeToken?.Invoke();
            return new(role, DateTimeOffset.MaxValue);
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(context, cancellationToken));
    }

    private sealed record RequestRow(HttpMethod Method, string Path, string Host, bool Authorized);
    private sealed class Backend(string role, WireState wire) : HttpMessageHandler
    {
        internal string Role => role;
        internal readonly List<RequestRow> Requests = [];
        internal bool Disposed;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(new(request.Method, request.RequestUri!.AbsolutePath, request.RequestUri.Host, request.Headers.Authorization is not null));
            return await wire.Respond(request, role, cancellationToken);
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }

    // State is changed by the transport, never by provisioner return values.
    private sealed class WireState
    {
        internal string VaultId = "", VaultName = "";
        internal JsonObject? Vault;
        internal bool Active, Deleted, Prejournaled = true, SecretReadDenied;
        internal string? Secret, ReadFault, CreateFault, DeleteFault, PurgeFault, SecretFault;
        internal string NativeStatus = "InProgress";
        internal readonly Dictionary<string, string> Children = new(StringComparer.Ordinal);
        internal readonly Dictionary<string, string> DeletedChildren = new(StringComparer.Ordinal);
        internal string? ChildFaultStep, ChildReplyFault;
        internal Action<string>? ChildAfterStep;
        internal Action<string> BeforeMutation = null!;
        internal TaskCompletionSource? Applied, Resume;
        internal TaskCompletionSource? ChildApplied, ChildResume;
        internal TaskCompletionSource? ChildBodyEntered, ChildBodyResume;
        internal void Seed(Provisioner.Plan plan, VaultAdministrationEffects.Configuration configuration, Guid nonce)
        {
            VaultId = plan.VaultId;
            VaultName = plan.VaultName;
            Vault = JsonNode.Parse(JsonSerializer.Serialize(new
            {
                id = VaultId,
                name = VaultName,
                type = "Microsoft.KeyVault/vaults",
                location = configuration.Location,
                tags = new Dictionary<string, string> { ["secretkit-fixture"] = nonce.ToString("N") },
                properties = new
                {
                    tenantId = configuration.TenantId,
                    sku = new { family = "A", name = configuration.Sku.ToString().ToLowerInvariant() },
                    enableRbacAuthorization = configuration.Rbac,
                    enableSoftDelete = true,
                    enablePurgeProtection = configuration.PurgeProtection,
                    softDeleteRetentionInDays = configuration.RetentionDays,
                    publicNetworkAccess = configuration.PublicNetworkAccess ? "Enabled" : "Disabled",
                    accessPolicies = configuration.Policies.Select(p => new
                    {
                        tenantId = p.TenantId,
                        objectId = p.PrincipalId,
                        applicationId = p.ApplicationId,
                        permissions = new { secrets = p.Permissions.Select(v => v.ToString().ToLowerInvariant()) }
                    }),
                    vaultUri = $"https://{VaultName}.vault.azure.net",
                    provisioningState = "Succeeded"
                }
            }))!.AsObject();
            Active = true;
        }
        internal async Task<HttpResponseMessage> Respond(HttpRequestMessage request, string role, CancellationToken token)
        {
            string path = request.RequestUri!.AbsolutePath;
            bool read = role.StartsWith("read", StringComparison.Ordinal);
            bool secret = role.EndsWith("secret", StringComparison.Ordinal);
            if (read && request.Method != HttpMethod.Get) throw new InvalidOperationException("observer-mutation");
            if (secret && request.Headers.Authorization is null)
            {
                var challenge = Json(401, "{}");
                challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                    $"Bearer authorization=\"https://login.microsoftonline.com/{Tenant:D}\", resource=\"https://vault.azure.net\"");
                return challenge;
            }
            if (request.Headers.Authorization?.Parameter != role) throw new InvalidOperationException("wrong-authority");
            if (request.RequestUri.Query != "?api-version=" + (secret ? "2025-07-01" : "2026-02-01"))
                throw new InvalidOperationException("wrong-revision");
            if (role == "denied-secret")
                return Json(403, """{"error":{"code":"Forbidden","message":"controlled-denial"}}""");
            if (read && ReadFault == "denied" || secret && read && SecretReadDenied)
                return Json(403, """{"error":{"code":"Forbidden","message":"protected-native-message"}}""");
            if (read && ReadFault == "oversized") return Json(200, "{\"padding\":\"" + new string('x', 70000) + "\"}");
            if (path.Contains("/operationResults/", StringComparison.Ordinal))
            {
                if (NativeStatus == "Succeeded" && Vault is not null) Vault["properties"]!["provisioningState"] = "Succeeded";
                return Json(200, JsonSerializer.Serialize(new { status = NativeStatus }));
            }
            if (secret)
            {
                if (path.TrimEnd('/') == "/secrets")
                    return Json(200, JsonSerializer.Serialize(new
                    {
                        value = Children.Keys.Append("canary").Select(n => new
                        {
                            id = $"https://{VaultName}.vault.azure.net/secrets/{n}",
                            attributes = new { enabled = true }
                        }).ToArray()
                    }));
                string name = path.Split('/')[2];
                if (name != "canary") return await PolicyChild(request, name, path, token);
                if (request.Method == HttpMethod.Put)
                {
                    BeforeMutation(path);
                    using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                    Secret = body.RootElement.GetProperty("value").GetString();
                }
                string payload = JsonSerializer.Serialize(new
                {
                    id = $"https://{VaultName}.vault.azure.net/secrets/canary/{Version}",
                    value = Secret,
                    attributes = new { enabled = true }
                });
                return Secret is null ? Missing() : request.Method == HttpMethod.Put
                    ? MutationResponse(SecretFault, 200, payload) : Json(200, payload);
            }
            if (request.Method == HttpMethod.Post)
            {
                BeforeMutation(path);
                Deleted = false;
                Secret = null;
                Children.Clear();
                DeletedChildren.Clear();
                return MutationResponse(PurgeFault, 200, "");
            }
            if (path.Contains("/deletedVaults/", StringComparison.Ordinal))
                return !Deleted ? Missing() : Json(200, JsonSerializer.Serialize(new
                {
                    id = path,
                    name = VaultName,
                    type = "Microsoft.KeyVault/deletedVaults",
                    properties = new
                    {
                        vaultId = VaultId,
                        location = "eastus",
                        tags = Vault!["tags"],
                        purgeProtectionEnabled = read && ReadFault == "deleted-protection" ||
                            Vault!["properties"]!["enablePurgeProtection"]!.GetValue<bool>(),
                        deletionDate = "2026-10-15T00:00:00Z",
                        scheduledPurgeDate = read && ReadFault == "deleted-retention"
                            ? "2026-10-15T00:00:01Z" : "2026-11-07T00:00:00Z"
                    }
                }));
            if (request.Method == HttpMethod.Put)
            {
                BeforeMutation(path);
                Vault = JsonNode.Parse(await request.Content!.ReadAsStringAsync(token))!.AsObject();
                Vault["id"] = path;
                Vault["name"] = VaultName;
                Vault["type"] = "Microsoft.KeyVault/vaults";
                Vault["properties"]!["vaultUri"] = $"https://{VaultName}.vault.azure.net";
                Vault["properties"]!["provisioningState"] = CreateFault is "async" or "202" ? "Creating" : "Succeeded";
                Active = true;
                Applied?.TrySetResult();
                if (Resume is not null) await Resume.Task;
                return MutationResponse(CreateFault == "async" ? "started" : CreateFault, 200, Vault.ToJsonString());
            }
            if (request.Method == HttpMethod.Delete)
            {
                BeforeMutation(path);
                Active = false;
                Deleted = true;
                return MutationResponse(DeleteFault, 204, "");
            }
            if (!Active) return Missing();
            var observed = Vault!.DeepClone().AsObject();
            if (read)
            {
                if (ReadFault == "nonce") observed["tags"]!["secretkit-fixture"] = Guid.NewGuid().ToString("N");
                if (ReadFault == "tenant") observed["properties"]!["tenantId"] = Guid.NewGuid().ToString();
                if (ReadFault == "configuration") observed["properties"]!["softDeleteRetentionInDays"] = 7;
                if (ReadFault == "partial") observed["properties"]!.AsObject().Remove("accessPolicies");
                if (ReadFault == "numeric-permission")
                    observed["properties"]!["accessPolicies"]![0]!["permissions"]!["secrets"]![0] =
                        ((int)SecretPermission.Get).ToString(System.Globalization.CultureInfo.InvariantCulture);
            }
            return Json(200, observed.ToJsonString());
        }
        private async Task<HttpResponseMessage> PolicyChild(HttpRequestMessage request, string name, string path, CancellationToken token)
        {
            bool deleted = path.StartsWith("/deletedsecrets/", StringComparison.Ordinal);
            if (request.Method == HttpMethod.Post && name == "restore")
            {
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                string encoded = body.RootElement.GetProperty("value").GetString()!;
                encoded = encoded.Replace('-', '+').Replace('_', '/');
                byte[] backup = Convert.FromBase64String(encoded.PadRight((encoded.Length + 3) / 4 * 4, '='));
                try
                {
                    string[] parts = Encoding.UTF8.GetString(backup).Split(':', 4);
                    if (parts.Length != 4 || parts[0] != "native" || parts[2] != Version)
                        throw new InvalidOperationException("invalid-native-backup");
                    name = parts[1];
                    Children.Add(name, parts[3]);
                }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(backup); }
            }
            else if (request.Method == HttpMethod.Post && deleted)
            {
                if (!DeletedChildren.Remove(name, out string? recovered))
                    throw new InvalidOperationException("missing-recovery");
                Children.Add(name, recovered);
                deleted = false;
            }
            string step = request.Method == HttpMethod.Put ? "set" :
                request.Method == HttpMethod.Post ? path.EndsWith("/backup", StringComparison.Ordinal) ? "backup" : "observe" :
                request.Method == HttpMethod.Delete ? deleted ? "purge" : "delete" : "observe";
            if (request.Method != HttpMethod.Get)
                BeforeMutation(path == "/secrets/restore" ? "/secrets/" + name : path);
            if (step == "set")
            {
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                Children.Add(name, body.RootElement.GetProperty("value").GetString()!);
                ChildApplied?.TrySetResult();
                if (ChildResume is not null) await ChildResume.Task;
            }
            if (step == "delete" && Children.Remove(name, out string? removed)) DeletedChildren.Add(name, removed);
            if (step == "purge") DeletedChildren.Remove(name);
            // The observe fault occurs only after the owned Set/delete/purge
            // history; preflight absence is still a well-formed native 404.
            if (ChildFaultStep == step && (step != "observe" || Children.Count + DeletedChildren.Count == 0 && ChildHistory))
                throw new IOException("protected-child-loss");
            if (step != "observe") ChildHistory = true;
            if (ChildReplyFault == "202" && step == "set") return Json(202, "{}");
            string? value = (deleted || step == "delete" ? DeletedChildren : Children).GetValueOrDefault(name);
            if (step == "purge")
            {
                ChildAfterStep?.Invoke(step);
                return Json(204, "");
            }
            if (step == "backup")
            {
                if (ChildReplyFault == "oversized") return Json(200, "{\"value\":\"" + new string('x', 70000) + "\"}");
                byte[] native = Encoding.UTF8.GetBytes("native:" + name + ":" + Version + ":" + Children[name]);
                string encoded = Convert.ToBase64String(native).TrimEnd('=').Replace('+', '-').Replace('/', '_');
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(native);
                ChildAfterStep?.Invoke(step);
                return Json(200, JsonSerializer.Serialize(new { value = ChildReplyFault == "backup" ? "!" : encoded }));
            }
            if (value is null) return Missing();
            string id = $"https://{VaultName}.vault.azure.net/secrets/{name}/{Version}";
            if (ChildReplyFault == "foreign") id = id.Replace("/secrets/" + name + "/", "/secrets/foreign/", StringComparison.Ordinal);
            var payload = new JsonObject
            {
                ["id"] = id,
                ["attributes"] = new JsonObject { ["enabled"] = true }
            };
            if (deleted || step == "delete")
            {
                payload["recoveryId"] = ChildReplyFault == "recovery" ? "https://foreign.invalid/deletedsecrets/" + name :
                    $"https://{VaultName}.vault.azure.net/deletedsecrets/{name}";
                payload["deletedDate"] = 1_760_486_400;
                payload["scheduledPurgeDate"] = 1_762_473_600;
            }
            else payload["value"] = ChildReplyFault == "wrong-value" ? "substituted" : value;
            if (ChildReplyFault == "version" && step == "delete")
                payload["id"] = id[..^32] + new string('b', 32);
            ChildAfterStep?.Invoke(step);
            var response = Json(200, ChildReplyFault == "duplicate" && step == "set"
                ? payload.ToJsonString()[..^1] + ",\"ID\":\"duplicate\"}" : payload.ToJsonString());
            if (ChildReplyFault == "headers" && step == "set") response.Headers.TryAddWithoutValidation("Location", "https://foreign.invalid");
            if (ChildReplyFault == "length" && step == "set") response.Content.Headers.ContentLength = 1;
            if (step == "set" && ChildBodyEntered is not null && ChildBodyResume is not null)
            {
                response.Content.Dispose();
                response.Content = new StreamContent(new ChildBodyStream(Encoding.UTF8.GetBytes(payload.ToJsonString()),
                    ChildBodyEntered, ChildBodyResume));
                response.Content.Headers.ContentType = new("application/json");
            }
            return response;
        }
        private bool ChildHistory;
        private sealed class ChildBodyStream(byte[] bytes, TaskCompletionSource entered, TaskCompletionSource resume) : MemoryStream(bytes)
        {
            private bool blocked;
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (!blocked)
                {
                    blocked = true;
                    entered.TrySetResult();
                    await resume.Task;
                }
                return base.Read(buffer.Span);
            }
            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
                ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        }
        private HttpResponseMessage MutationResponse(string? fault, int status, string body)
        {
            if (fault == "lost") throw new IOException("protected-native-message");
            if (fault == "malformed") return Json(200, "{");
            bool asynchronous = fault is "async" or "started" or "202" or "foreign-status";
            var response = Json(fault == "started" ? 201 : asynchronous ? 202 : status, body);
            if (asynchronous)
                response.Headers.TryAddWithoutValidation("Azure-AsyncOperation",
                    (fault == "foreign-status" ? "https://foreign.invalid" : "https://management.azure.com") +
                    $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/operationResults/44444444-4444-4444-4444-444444444444?api-version=2026-02-01");
            return response;
        }
        private static HttpResponseMessage Missing() => Json(404, """{"error":{"code":"NotFound"}}""");
        private static HttpResponseMessage Json(int status, string body)
        {
            var response = new HttpResponseMessage((HttpStatusCode)status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
            response.Headers.TryAddWithoutValidation("x-ms-request-id", Guid.NewGuid().ToString("D"));
            return response;
        }
    }
}
