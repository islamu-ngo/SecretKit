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
    public async Task OriginalSubscriptionVaultInventoryUsesCompleteMembershipAndFreshParent(string boundary)
    {
        await using var f = new ReadServiceFixture(boundary, subscriptionList: true);
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        await Assert.That(f.MetadataGets).IsEqualTo(2);
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(3);
        await Assert.That(f.Native.Read().Resources.Any(r => r.SelectedAttempted)).IsFalse();
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments(1, 1, false)]
    [Arguments(1, 1, true)]
    [Arguments(4, 16, false)]
    [Arguments(4, 16, true)]
    public async Task SubscriptionVaultInventoryPreservesOriginalSubscriptionAndConstructsGroupScope(
        int pages, int items, bool nullNext)
    {
        var limits = new CollectionLimits(pages, items, TimeSpan.FromSeconds(20));
        await using var f = new ReadServiceFixture(subscriptionList: true, limits: limits);
        var lease = await f.PrepareAndBaseline();
        if (nullNext) f.Fault = "selected-null-continuation";
        var scope = new SubscriptionScope(Subscription);
        var result = await f.StartSubscription(scope);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Complete).IsTrue();
        await Assert.That(result.Items.Count).IsEqualTo(1);
        var row = result.Items.Single();
        await Assert.That(ReferenceEquals(row.Scope.ResourceGroup.Subscription, scope)).IsTrue();
        await Assert.That(row.Scope.ResourceGroup.ResourceGroup).IsEqualTo("fixture-group");
        await Assert.That(row.Scope.VaultName).IsEqualTo(lease.VaultName);
        await Assert.That((await f.ObserveGroup()).Vaults.Count).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selected-id")]
    [Arguments("selected-foreign-group")]
    [Arguments("selected-name")]
    [Arguments("selected-type")]
    [Arguments("selected-location")]
    [Arguments("selected-tag")]
    [Arguments("selected-extra-tag")]
    [Arguments("selected-missing-id")]
    [Arguments("selected-case-id")]
    [Arguments("selected-provisioning")]
    [Arguments("selected-rbac")]
    [Arguments("selected-purge")]
    [Arguments("selected-retention")]
    [Arguments("selected-soft-delete")]
    [Arguments("selected-tenant")]
    [Arguments("selected-sku")]
    [Arguments("selected-public")]
    [Arguments("selected-uri")]
    [Arguments("selected-missing-policies")]
    [Arguments("selected-null-policies")]
    [Arguments("selected-create-mode")]
    [Arguments("selected-create-mode-case")]
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
    [Arguments("denial-without-response")]
    public async Task SubscriptionVaultInventoryCannotFilterOrPromoteInvalidNativeMembership(string fault)
    {
        await using var f = new ReadServiceFixture(subscriptionList: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedGets).IsEqualTo(1);
    }

    [Test]
    [Arguments("baseline-id")]
    [Arguments("baseline-foreign-group")]
    [Arguments("baseline-tag")]
    [Arguments("baseline-provisioning")]
    [Arguments("baseline-empty")]
    [Arguments("baseline-foreign-row")]
    [Arguments("baseline-continuation")]
    [Arguments("baseline-numeric-continuation")]
    [Arguments("baseline-null-policies")]
    [Arguments("baseline-create-mode-case")]
    [Arguments("post-id")]
    [Arguments("post-foreign-group")]
    [Arguments("post-tag")]
    [Arguments("post-rbac")]
    [Arguments("post-retention")]
    [Arguments("post-empty")]
    [Arguments("post-foreign-row")]
    [Arguments("post-continuation")]
    [Arguments("post-empty-continuation")]
    [Arguments("post-create-mode-case")]
    public async Task SubscriptionVaultInventoryNeedsIndependentUnfilteredFrozenBaselineAndPost(string fault)
    {
        await using var f = new ReadServiceFixture(subscriptionList: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedGets).IsEqualTo(fault.StartsWith("baseline-", StringComparison.Ordinal) ? 0 : 1);
    }

    [Test]
    public async Task SubscriptionVaultInventoryWrongScopeAndHooksCannotStealOriginalAdmission()
    {
        await using var f = new ReadServiceFixture(subscriptionList: true);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(async () => await f.StartSubscription(new(Guid.NewGuid()))).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.StartGroup()).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedGets).IsEqualTo(0);
        await Assert.That((await f.StartSubscription()).Complete).IsTrue();
        await Assert.That(async () => await f.StartSubscription()).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OtherOrdinaryReadProfilesCannotBorrowSubscriptionInventoryHook(bool group)
    {
        await using var f = new ReadServiceFixture(groupList: group);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(async () => await f.StartSubscription()).Throws<InvalidOperationException>();
        if (group) await Assert.That((await f.StartGroup()).Complete).IsTrue();
        else await Assert.That((await f.Start(lease)).Status).IsEqualTo(SecretStatus.Success);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task SubscriptionVaultInventoryForeignActualClientCannotConsumeRegisteredSelection()
    {
        await using var f = new ReadServiceFixture(subscriptionList: true);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(async () => await f.Source.RunListVaultsSubscriptionAsync(f.Native.Selector,
            f.GroupClient(bypass: true), new(Subscription), f.OriginalLimits, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        await Assert.That((await f.StartSubscription()).Complete).IsTrue();
        await Assert.That(f.SelectedGets).IsEqualTo(2);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task SubscriptionVaultInventoryNativeDenialRetainsIncompleteEmptyInventory()
    {
        await using var f = new ReadServiceFixture(subscriptionList: true);
        var lease = await f.PrepareAndBaseline();
        var result = await f.Source.RunListVaultsSubscriptionAsync(f.Native.Selector,
            new(new Credential("denied-arm"), f.Source.SelectedTransport),
            new(Subscription), f.OriginalLimits, default);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(result.Complete || result.Items.Count != 0).IsFalse();
        await f.ObserveGroup();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SubscriptionVaultInventoryRestartCannotReconstructOriginalReadCapability(bool selected)
    {
        await using var f = new ReadServiceFixture(subscriptionList: true);
        var lease = await f.PrepareAndBaseline();
        if (selected) await f.StartSubscription();
        await using var restarted = f.Reopen();
        await Assert.That(async () => await restarted.RunListVaultsSubscriptionAsync(f.Native.Selector,
            f.GroupClient(), new(Subscription), f.OriginalLimits, default)).Throws<InvalidOperationException>();
        using var observer = f.ObserverFor(restarted);
        RoleFixtureRelease.Validate(await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task SubscriptionVaultInventoryTimerFailureCannotLeakTheOriginalLoan()
    {
        var clock = new ReadTimer();
        await using var f = new ReadServiceFixture(time: clock, subscriptionList: true);
        var lease = await f.PrepareAndBaseline();
        clock.Fail = true;
        await Assert.That(async () => await f.StartSubscription()).Throws<InvalidOperationException>();
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
    [Arguments("read-metadata-arm", "credential", true)]
    [Arguments("read-metadata-arm", "transport", false)]
    [Arguments("read-metadata-arm", "body", true)]
    [Arguments("read-metadata-arm", "sdk", false)]
    [Arguments("read-arm", "credential", false)]
    [Arguments("read-arm", "transport", true)]
    [Arguments("read-arm", "body", false)]
    [Arguments("read-arm", "sdk", true)]
    [Arguments("deleted-reader-arm", "credential", true)]
    [Arguments("deleted-reader-arm", "transport", false)]
    [Arguments("deleted-reader-arm", "body", true)]
    [Arguments("deleted-reader-arm", "sdk", false)]
    public async Task SubscriptionVaultInventoryCloseDrainsActualInventoryAndParentBorrowers(string role, string stage, bool dispose)
    {
        await using var f = new ReadServiceFixture(subscriptionList: true);
        var lease = await f.PrepareAndBaseline();
        bool selected = role.StartsWith("selected", StringComparison.Ordinal);
        if (!selected) await f.StartSubscription();
        f.Barrier = role + "-" + stage;
        Task borrowed = selected ? f.StartSubscription() : f.ObserveGroup().AsTask();
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
    }
}
