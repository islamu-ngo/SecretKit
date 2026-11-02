using SecretKit.AzureKeyVault.Conformance.Tests.Admission;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalDeletedInventoryJoinsActualSetupDeleteAndPurgeOnlyCleanup(string boundary)
    {
        await using var f = new DeletedReadFixture(boundary, inventory: true);
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        await Assert.That(f.MetadataGets).IsEqualTo(2);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.Purges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(3);
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Native.Wire.VaultId).DeleteAttempted).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => r.SelectedAttempted)).IsFalse();
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments(1, 1, false)]
    [Arguments(1, 1, true)]
    [Arguments(4, 16, false)]
    [Arguments(4, 16, true)]
    public async Task DeletedInventoryPreservesOriginalSubscriptionAndActualDeletedMetadata(int pages, int items, bool nullNext)
    {
        var limits = new CollectionLimits(pages, items, TimeSpan.FromSeconds(20));
        await using var f = new DeletedReadFixture(inventory: true, limits: limits);
        var lease = await f.PrepareAndBaseline();
        if (nullNext) f.Fault = "selected-null-continuation";
        var scope = new SubscriptionScope(Subscription);
        var result = await f.StartList(scope);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Complete).IsTrue();
        await Assert.That(result.Items.Count).IsEqualTo(1);
        var row = result.Items.Single();
        await Assert.That(ReferenceEquals(row.Scope.Subscription, scope)).IsTrue();
        await Assert.That(row.Scope.Location).IsEqualTo("eastus");
        await Assert.That(row.Scope.VaultName).IsEqualTo(lease.VaultName);
        await Assert.That(row.PurgeProtected).IsFalse();
        await Assert.That(row.ScheduledPurgeOn - row.DeletedOn).IsEqualTo(TimeSpan.FromDays(23));
        var post = await f.Post();
        await Assert.That(post.VaultStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(post.DeletedVaultStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(post.Configuration).IsNull();
        await Assert.That(post.Policies.Length).IsEqualTo(0);
        await Assert.That(post.DeletedVaults.Length).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selected-id")]
    [Arguments("selected-case-id")]
    [Arguments("selected-location-id")]
    [Arguments("selected-name")]
    [Arguments("selected-type")]
    [Arguments("selected-missing-id")]
    [Arguments("selected-duplicate-id")]
    [Arguments("selected-vault")]
    [Arguments("selected-group")]
    [Arguments("selected-owner")]
    [Arguments("selected-extra-tag")]
    [Arguments("selected-location")]
    [Arguments("selected-protection")]
    [Arguments("selected-null-protection")]
    [Arguments("selected-missing-protection")]
    [Arguments("selected-date")]
    [Arguments("selected-null-date")]
    [Arguments("selected-invalid-date")]
    [Arguments("selected-purge-date")]
    [Arguments("selected-shifted-dates")]
    [Arguments("selected-extra-property")]
    [Arguments("selected-empty")]
    [Arguments("selected-duplicate")]
    [Arguments("selected-foreign-row")]
    [Arguments("selected-missing")]
    [Arguments("selected-error")]
    [Arguments("selected-partial")]
    [Arguments("selected-malformed")]
    [Arguments("selected-oversized")]
    [Arguments("selected-duplicate-field")]
    [Arguments("selected-continuation")]
    [Arguments("selected-foreign-continuation")]
    [Arguments("selected-empty-continuation")]
    [Arguments("selected-numeric-continuation")]
    [Arguments("selected-bool-continuation")]
    [Arguments("selected-array-continuation")]
    [Arguments("selected-object-continuation")]
    [Arguments("denial-without-response")]
    public async Task DeletedInventoryCannotPromoteUnboundPartialOrFilteredMembership(string fault)
    {
        await using var f = new DeletedReadFixture(inventory: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
    }

    [Test]
    [Arguments("baseline-vault")]
    [Arguments("baseline-location-id")]
    [Arguments("baseline-owner")]
    [Arguments("baseline-empty")]
    [Arguments("baseline-foreign-row")]
    [Arguments("baseline-continuation")]
    [Arguments("baseline-bool-continuation")]
    [Arguments("baseline-null-protection")]
    [Arguments("post-vault")]
    [Arguments("post-location")]
    [Arguments("post-owner")]
    [Arguments("post-shifted-dates")]
    [Arguments("post-empty")]
    [Arguments("post-foreign-row")]
    [Arguments("post-continuation")]
    [Arguments("post-object-continuation")]
    public async Task DeletedInventoryNeedsFreshIndependentWholeMembershipAndFrozenDates(string fault)
    {
        await using var f = new DeletedReadFixture(inventory: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedGets).IsEqualTo(fault.StartsWith("baseline-", StringComparison.Ordinal) ? 0 : 1);
    }

    [Test]
    [Arguments("parent-owner")]
    [Arguments("parent-protection")]
    [Arguments("parent-date")]
    public async Task DeletedInventoryCannotPurgeWhenFreshNativeParentDisagrees(string fault)
    {
        await using var f = new DeletedReadFixture(inventory: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.Purges).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DeletedInventoryRejectsMissingDeletedOnlyCleanupAuthority(bool explicitFalse)
    {
        await using var f = new DeletedReadFixture(inventory: true);
        var lease = await f.PrepareAndBaseline();
        if (explicitFalse)
            await Assert.That(async () => await f.Parent.ReleaseAsync(Owner, f.Native.Selector, purge: true,
                requireOriginalDeletedReadRoot: false)).Throws<InvalidOperationException>();
        else
            await Assert.That(async () => await f.Parent.ReleaseAsync(Owner, f.Native.Selector, purge: true))
                .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Closing).IsFalse();
        await Assert.That(f.Purges).IsEqualTo(0);
        await Assert.That((await f.StartList()).Complete).IsTrue();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task DeletedInventoryCleanupNeverDeletesAReappearedActiveVault()
    {
        await using var f = new DeletedReadFixture(inventory: true);
        await f.PrepareAndBaseline();
        f.Native.Wire.Active = true;
        await f.Release();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.Purges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Native.Wire.VaultId).DeleteAttempted).IsFalse();
    }

    [Test]
    [Arguments("create")]
    [Arguments("preparation")]
    [Arguments("purge")]
    public async Task DeletedInventoryNeverReplaysUnknownPreparationOrCleanup(string phase)
    {
        await using var f = new DeletedReadFixture(inventory: true);
        if (phase == "create") f.Native.Wire.CreateFault = "lost";
        if (phase == "preparation") f.Native.Wire.DeleteFault = "lost";
        if (phase == "purge") f.Native.Wire.PurgeFault = "lost";
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await f.Release();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SetupDeletes).IsEqualTo(phase == "create" ? 0 : 1);
        await Assert.That(f.Purges).IsEqualTo(phase == "purge" ? 1 : 0);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    public async Task DeletedInventoryWrongScopeAndGetHookCannotConsumeOriginalAdmission()
    {
        await using var f = new DeletedReadFixture(inventory: true);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(async () => await f.StartList(new(Guid.NewGuid()))).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedGets).IsEqualTo(0);
        await Assert.That((await f.StartList()).Complete).IsTrue();
        await Assert.That(async () => await f.StartList()).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task GetDeletedProfileCannotBorrowInventoryHook()
    {
        await using var f = new DeletedReadFixture();
        var lease = await f.PrepareAndBaseline();
        await Assert.That(async () => await f.StartList()).Throws<InvalidOperationException>();
        await Assert.That((await f.Start(lease)).Status).IsEqualTo(SecretStatus.Success);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task DeletedInventoryForeignActualClientCannotConsumeRegisteredSelection()
    {
        await using var f = new DeletedReadFixture(inventory: true);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(async () => await f.Source.RunListDeletedVaultsAsync(f.Native.Selector,
            f.ListClient(bypass: true), new(Subscription), f.OriginalLimits, default)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        await Assert.That((await f.StartList()).Complete).IsTrue();
        await Assert.That(f.SelectedGets).IsEqualTo(2);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(401)]
    [Arguments(403)]
    public async Task DeletedInventoryRequiresNativeDenialAndReturnsIncompleteEmptyInventory(int status)
    {
        await using var f = new DeletedReadFixture(inventory: true) { DenialStatus = status };
        var lease = await f.PrepareAndBaseline();
        var result = await f.Source.RunListDeletedVaultsAsync(f.Native.Selector,
            new(new Credential("denied-arm"), f.Source.SelectedTransport), new(Subscription), f.OriginalLimits, default);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(result.Complete || result.Items.Count != 0).IsFalse();
        await f.Post();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DeletedInventoryRestartOnlyRecoversPurgeCleanupCoordinates(bool selected)
    {
        await using var f = new DeletedReadFixture(inventory: true);
        var lease = await f.PrepareAndBaseline();
        if (selected) await f.StartList();
        await using var restarted = f.Reopen();
        await Assert.That(async () => await restarted.RunListDeletedVaultsAsync(f.Native.Selector,
            f.ListClient(), new(Subscription), f.OriginalLimits, default)).Throws<InvalidOperationException>();
        using var observer = f.ObserverFor(restarted);
        RoleFixtureRelease.Validate(await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default), f.Native.Selector, lease.Facts);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
    }

    [Test]
    public async Task DeletedInventoryTimerFailureCannotLeakItsOriginalLoan()
    {
        var clock = new ReadTimer();
        await using var f = new DeletedReadFixture(time: clock, inventory: true);
        var lease = await f.PrepareAndBaseline();
        clock.Fail = true;
        await Assert.That(async () => await f.StartList()).Throws<InvalidOperationException>();
        clock.Fail = false;
        await Assert.That(f.Native.Read().Idle).IsTrue();
        await Assert.That(f.SelectedGets).IsEqualTo(0);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selected-arm", "credential", false)]
    [Arguments("selected-arm", "transport", true)]
    [Arguments("selected-arm", "body", false)]
    [Arguments("selected-original", "sdk", true)]
    [Arguments("read-deleted-metadata-arm", "credential", true)]
    [Arguments("read-deleted-metadata-arm", "transport", false)]
    [Arguments("read-deleted-metadata-arm", "body", true)]
    [Arguments("read-deleted-metadata-arm", "sdk", false)]
    [Arguments("read-arm", "credential", false)]
    [Arguments("read-arm", "transport", true)]
    [Arguments("read-arm", "body", false)]
    [Arguments("read-arm", "sdk", true)]
    [Arguments("deleted-parent-arm", "credential", true)]
    [Arguments("deleted-parent-arm", "transport", false)]
    [Arguments("deleted-parent-arm", "body", true)]
    [Arguments("deleted-parent-arm", "sdk", false)]
    public async Task DeletedInventoryCloseDrainsActualCollectionAndBothParentBorrowers(string role, string stage, bool dispose)
    {
        await using var f = new DeletedReadFixture(inventory: true);
        await f.PrepareAndBaseline();
        bool selected = role.StartsWith("selected", StringComparison.Ordinal);
        if (!selected) await f.StartList();
        f.Barrier = role + "-" + stage;
        Task borrowed = selected ? f.StartList() : f.Post().AsTask();
        Task closing = Task.CompletedTask;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            closing = dispose ? f.Source.DisposeAsync().AsTask() : f.Release().AsTask();
            await Assert.That(f.Native.Read().Closing).IsTrue();
            await Assert.That(closing.IsCompleted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        bool rejected = false;
        try { await borrowed.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception failure) when (failure is OperationCanceledException or NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
        await closing.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Idle).IsTrue();
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
    }
}
