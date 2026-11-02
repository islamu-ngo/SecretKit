using SecretKit.AzureKeyVault.Conformance.Tests.Admission;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Effects = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalPrivateLinkInventoryJoinsFreshChildAndNativeLinkMetadata(string boundary)
    {
        await using var f = new PrivateReadFixture(boundary, links: true);
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        await Assert.That(f.SelectedReads).IsEqualTo(1);
        await Assert.That(f.ChildObservations >= 2).IsTrue();
        await Assert.That(f.LinkQueries).IsEqualTo(3);
        await Assert.That(f.PrivateReads >= 2 && f.PublicReads >= 2).IsTrue();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(5);
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.SelectedAttempted).IsFalse();
        await Assert.That(f.Endpoint!.EndpointExists || f.Endpoint.NicExists).IsFalse();
    }

    [Test]
    [Arguments(1, 1, false, false)]
    [Arguments(1, 1, true, true)]
    [Arguments(4, 16, false, true)]
    [Arguments(4, 16, true, false)]
    public async Task PrivateLinkInventoryFreezesActualBaselineArraysAndPreservesOriginalLimits(
        int pages, int items, bool empty, bool nullContinuation)
    {
        var limits = new CollectionLimits(pages, items, TimeSpan.FromSeconds(20));
        await using var f = new PrivateReadFixture(links: true, limits: limits);
        if (empty) { f.LinkMembers = []; f.LinkZones = []; }
        var lease = await f.PrepareAndBaseline();
        if (nullContinuation) f.Fault = "selected-null-continuation";
        var result = await f.StartLinks(lease);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Complete).IsTrue();
        await Assert.That(result.Items.Count).IsEqualTo(1);
        var link = result.Items.Single();
        await Assert.That(link.Name == "vault" && link.GroupId == "vault").IsTrue();
        await Assert.That(link.RequiredMembers.SequenceEqual(f.LinkMembers)).IsTrue();
        await Assert.That(link.RequiredZoneNames.SequenceEqual(f.LinkZones)).IsTrue();
        await Assert.That(ReferenceEquals(limits, f.OriginalLimits)).IsTrue();
        var observed = await f.Observe(lease);
        await Assert.That(observed.Connections.Single().Name).IsEqualTo(lease.PrivateConnectionName);
        await Assert.That(observed.PrivateLinks.Single().RequiredMembers.SequenceEqual(f.LinkMembers)).IsTrue();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selected-id")]
    [Arguments("selected-name")]
    [Arguments("selected-type")]
    [Arguments("selected-group")]
    [Arguments("selected-members")]
    [Arguments("selected-zones")]
    [Arguments("selected-member-order")]
    [Arguments("selected-zone-order")]
    [Arguments("selected-member-case")]
    [Arguments("selected-zone-case")]
    [Arguments("selected-duplicate-member")]
    [Arguments("selected-duplicate-zone")]
    [Arguments("selected-null-members")]
    [Arguments("selected-missing-zones")]
    [Arguments("selected-numeric-member")]
    [Arguments("selected-too-many-members")]
    [Arguments("selected-case-property")]
    [Arguments("selected-empty")]
    [Arguments("selected-duplicate")]
    [Arguments("selected-missing")]
    [Arguments("selected-shape")]
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
    public async Task PrivateLinkInventoryCannotPromoteUnboundOrIncompleteNativeMetadata(string fault)
    {
        await using var f = new PrivateReadFixture(links: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedReads).IsEqualTo(1);
    }

    [Test]
    [Arguments("baseline-child")]
    [Arguments("baseline-id")]
    [Arguments("baseline-group")]
    [Arguments("baseline-duplicate-member")]
    [Arguments("baseline-null-members")]
    [Arguments("baseline-empty")]
    [Arguments("baseline-continuation")]
    [Arguments("baseline-error")]
    [Arguments("post-child")]
    [Arguments("post-id")]
    [Arguments("post-group")]
    [Arguments("post-members")]
    [Arguments("post-zones")]
    [Arguments("post-member-order")]
    [Arguments("post-zone-order")]
    [Arguments("post-member-case")]
    [Arguments("post-zone-case")]
    [Arguments("post-empty")]
    [Arguments("post-continuation")]
    [Arguments("post-error")]
    public async Task PrivateLinkInventoryRequiresFreshIndependentChildAndFrozenLinkFacts(string fault)
    {
        await using var f = new PrivateReadFixture(links: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedReads).IsEqualTo(fault.StartsWith("baseline-", StringComparison.Ordinal) ? 0 : 1);
    }

    [Test]
    public async Task PrivateLinkInventoryCannotRefreshItsBaselineAfterMetadataChanges()
    {
        await using var f = new PrivateReadFixture(links: true);
        var lease = await f.PrepareAndBaseline();
        f.LinkMembers = ["changed-after-baseline"];
        await Assert.That(async () => await f.StartLinks(lease)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedReads).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task PrivateLinkInventoryNativeDenialIsIncompleteAndEmpty()
    {
        await using var f = new PrivateReadFixture(links: true);
        var lease = await f.PrepareAndBaseline();
        var result = await f.Source.RunListPrivateLinkResourcesAsync(f.Native.Selector, f.Client("denied-arm"),
            f.Scope(lease).Vault, f.OriginalLimits, default);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(result.Complete || result.Items.Count != 0).IsFalse();
        var observed = await f.Observe(lease);
        await Assert.That(observed.ConnectionState).IsEqualTo(PrivateConnectionState.Pending);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task PrivateLinkInventoryForeignClientAndWrongHooksDoNotConsumeValidAdmission()
    {
        await using var f = new PrivateReadFixture(links: true);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(async () => await f.Source.RunGetPrivateConnectionAsync(f.Native.Selector, f.Client(),
            f.Scope(lease), default)).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Source.RunListPrivateConnectionsAsync(f.Native.Selector, f.Client(),
            f.Scope(lease).Vault, f.OriginalLimits, default)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedReads).IsEqualTo(0);
        await Assert.That(async () => await f.Source.RunListPrivateLinkResourcesAsync(f.Native.Selector,
            f.Client(bypassSource: true), f.Scope(lease).Vault, f.OriginalLimits, default)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedReads).IsEqualTo(1);
        await Assert.That((await f.StartLinks(lease)).Complete).IsTrue();
        await Assert.That(async () => await f.StartLinks(lease)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedReads).IsEqualTo(2);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OtherPrivateReadProfilesCannotBorrowTheLinkInventoryHook(bool inventory)
    {
        await using var f = new PrivateReadFixture(inventory: inventory);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(async () => await f.Source.RunListPrivateLinkResourcesAsync(f.Native.Selector, f.Client(),
            f.Scope(lease).Vault, f.OriginalLimits, default)).Throws<InvalidOperationException>();
        if (inventory) await Assert.That((await f.StartInventory(lease)).Complete).IsTrue();
        else await Assert.That((await f.Start(lease)).Status).IsEqualTo(SecretStatus.Success);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task PrivateLinkInventoryRequiresItsExplicitAuthoritiesBeforeSetup()
    {
        await using var f = new PrivateReadFixture(links: true);
        await using var source = f.Reopen(omitPrivate: true);
        using var observer = PrivateReadFixture.ObserverFor(source);
        await Assert.That(async () => await observer.PostAsync<Effects.Prepare, Effects.Lease>("vault/prepare",
            f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Wire.Active || f.Endpoint is not null).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PrivateLinkInventoryRestartOnlyRecoversCleanupCoordinates(bool afterRead)
    {
        await using var f = new PrivateReadFixture(links: true);
        var lease = await f.PrepareAndBaseline();
        if (afterRead) await f.StartLinks(lease);
        await using var restarted = f.Reopen();
        await Assert.That(async () => await restarted.RunListPrivateLinkResourcesAsync(f.Native.Selector,
            f.Client(), f.Scope(lease).Vault, f.OriginalLimits, default)).Throws<InvalidOperationException>();
        using var observer = PrivateReadFixture.ObserverFor(restarted);
        RoleFixtureRelease.Validate(await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selected-arm", "credential", false)]
    [Arguments("selected-arm", "transport", true)]
    [Arguments("selected-arm", "body", false)]
    [Arguments("selected-original", "sdk", true)]
    [Arguments("connection-reader-arm", "credential", false)]
    [Arguments("connection-reader-arm", "transport", true)]
    [Arguments("connection-reader-arm", "body", false)]
    [Arguments("connection-reader-arm", "sdk", true)]
    [Arguments("link-reader-arm", "credential", false)]
    [Arguments("link-reader-arm", "transport", true)]
    [Arguments("link-reader-arm", "body", false)]
    [Arguments("link-reader-arm", "sdk", true)]
    [Arguments("endpoint-reader-arm", "credential", true)]
    [Arguments("endpoint-reader-arm", "transport", false)]
    [Arguments("endpoint-reader-arm", "body", true)]
    [Arguments("endpoint-reader-arm", "sdk", false)]
    [Arguments("read-arm", "credential", false)]
    [Arguments("read-arm", "transport", true)]
    [Arguments("read-arm", "body", false)]
    [Arguments("read-arm", "sdk", true)]
    [Arguments("read-secret", "credential", true)]
    [Arguments("read-secret", "transport", false)]
    [Arguments("read-secret", "body", true)]
    [Arguments("read-secret", "sdk", false)]
    [Arguments("private-runtime-secret", "credential", false)]
    [Arguments("private-runtime-secret", "transport", true)]
    [Arguments("private-runtime-secret", "body", false)]
    [Arguments("private-runtime-secret", "sdk", true)]
    [Arguments("public-runtime-secret", "credential", true)]
    [Arguments("public-runtime-secret", "transport", false)]
    [Arguments("public-runtime-secret", "body", true)]
    [Arguments("public-runtime-secret", "sdk", false)]
    public async Task PrivateLinkInventoryClosureJoinsBothMetadataReadsAndAllActualBorrowers(string role, string stage, bool dispose)
    {
        await using var f = new PrivateReadFixture(links: true);
        var lease = await f.PrepareAndBaseline();
        bool selected = role.StartsWith("selected", StringComparison.Ordinal);
        if (!selected) await f.StartLinks(lease);
        f.Barrier = role + "-" + stage;
        Task borrowed = selected ? f.StartLinks(lease) : f.Observe(lease).AsTask();
        Task closing = Task.CompletedTask;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            closing = dispose ? f.Source.DisposeAsync().AsTask() : f.Release().AsTask();
            await Assert.That(f.Native.Read().Closing).IsTrue();
            await Assert.That(closing.IsCompleted).IsFalse();
            await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.SelectedAttempted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        bool rejected = false;
        try { await borrowed.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception failure) when (failure is OperationCanceledException or NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
        await closing.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(Guid.Empty);
    }
}
