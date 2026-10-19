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
    public async Task PrivateInventoryCannotQualifyAForeignClientOrConsumeTheOriginalAdmission()
    {
        await using var f = new PrivateReadFixture(inventory: true);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(async () => await f.Source.RunListPrivateConnectionsAsync(f.Native.Selector,
            f.Client(bypassSource: true), f.Scope(lease).Vault, f.OriginalLimits, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.SelectedReads).IsEqualTo(1);
        await Assert.That((await f.StartInventory(lease)).Complete).IsTrue();
        await Assert.That(f.SelectedReads).IsEqualTo(2);
        await f.Observe(lease);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task PrivateInventoryRestartCannotEraseTheOutstandingOriginalReadFence()
    {
        await using var f = new PrivateReadFixture(inventory: true);
        var lease = await f.PrepareAndBaseline();
        f.Barrier = "selected-original-sdk";
        var read = f.StartInventory(lease);
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var dispatch = f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch;
            await using var restarted = f.Reopen();
            using var observer = PrivateReadFixture.ObserverFor(restarted);
            await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
                "vault/release", f.Native.Selector, default);
            await Assert.That(f.Native.Read().Closing).IsTrue();
            await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(dispatch);
            await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.InvocationTerminated).IsFalse();
            await Assert.That(f.Endpoint!.Requests.Any(r => r.Method == "DELETE")).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        await read.WaitAsync(TimeSpan.FromSeconds(10));
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalPrivateConnectionInventoryComposesCompleteOwnedNativeMembership(string boundary)
    {
        await using var f = new PrivateReadFixture(boundary, inventory: true);
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        await Assert.That(f.SelectedReads).IsEqualTo(1);
        await Assert.That(f.PrivateReads >= 2 && f.PublicReads >= 2).IsTrue();
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.SelectedAttempted).IsFalse();
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(f.Endpoint!.EndpointExists || f.Endpoint.NicExists).IsFalse();
    }

    [Test]
    [Arguments(1, 1, false)]
    [Arguments(1, 1, true)]
    [Arguments(4, 16, false)]
    [Arguments(4, 16, true)]
    public async Task PrivateInventoryUsesOriginalScopeAndLimitsForTheActualCompleteSingleton(int pages, int items, bool nullContinuation)
    {
        var limits = new CollectionLimits(pages, items, TimeSpan.FromSeconds(20));
        await using var f = new PrivateReadFixture(inventory: true, limits: limits);
        var lease = await f.PrepareAndBaseline();
        if (nullContinuation) f.Fault = "selected-null-continuation";
        var actual = await f.StartInventory(lease);
        await Assert.That(actual.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(actual.Complete).IsTrue();
        await Assert.That(actual.Items.Count).IsEqualTo(1);
        await Assert.That(ReferenceEquals(actual.Items.Single().Scope.Vault, f.OriginalListScope)).IsTrue();
        await Assert.That(actual.Items.Single().Scope.ConnectionName).IsEqualTo(lease.PrivateConnectionName);
        await Assert.That(actual.Items.Single().State).IsEqualTo(PrivateConnectionState.Pending);
        await Assert.That(ReferenceEquals(limits, f.OriginalLimits)).IsTrue();
        await f.Observe(lease);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selected-empty")]
    [Arguments("selected-missing")]
    [Arguments("selected-shape")]
    [Arguments("selected-extra")]
    [Arguments("selected-duplicate")]
    [Arguments("selected-duplicate-field")]
    [Arguments("selected-case-field")]
    [Arguments("selected-case-row")]
    [Arguments("selected-endpoint")]
    [Arguments("selected-id")]
    [Arguments("selected-name")]
    [Arguments("selected-type")]
    [Arguments("selected-state")]
    [Arguments("selected-error")]
    [Arguments("selected-partial")]
    [Arguments("selected-malformed")]
    [Arguments("selected-oversized")]
    [Arguments("selected-continuation")]
    [Arguments("selected-foreign-continuation")]
    [Arguments("selected-empty-continuation")]
    [Arguments("selected-numeric-continuation")]
    [Arguments("denial-without-response")]
    public async Task PrivateInventoryCannotPromoteIncompleteForeignOrAmbiguousNativeRows(string fault)
    {
        await using var f = new PrivateReadFixture(inventory: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedReads).IsEqualTo(1);
    }

    [Test]
    [Arguments("baseline-empty")]
    [Arguments("baseline-extra")]
    [Arguments("baseline-endpoint")]
    [Arguments("baseline-continuation")]
    [Arguments("baseline-error")]
    [Arguments("post-empty")]
    [Arguments("post-extra")]
    [Arguments("post-endpoint")]
    [Arguments("post-continuation")]
    [Arguments("post-error")]
    public async Task PrivateInventoryRequiresFreshCompleteIndependentMembership(string fault)
    {
        await using var f = new PrivateReadFixture(inventory: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedReads).IsEqualTo(fault.StartsWith("baseline-", StringComparison.Ordinal) ? 0 : 1);
    }

    [Test]
    public async Task PrivateInventoryDenialIsTheActualIncompleteEmptyNativeResult()
    {
        await using var f = new PrivateReadFixture(inventory: true);
        var lease = await f.PrepareAndBaseline();
        var scope = f.Scope(lease).Vault;
        var actual = await f.Source.RunListPrivateConnectionsAsync(f.Native.Selector, f.Client("denied-arm"),
            scope, f.OriginalLimits, default);
        await Assert.That(actual.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(actual.Complete).IsFalse();
        await Assert.That(actual.Items.Count).IsEqualTo(0);
        await f.Observe(lease);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task PrivateInventoryCannotUseTheSingleReadHookOrConsumeAdmissionWithForeignScope()
    {
        await using var f = new PrivateReadFixture(inventory: true);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(async () => await f.Source.RunGetPrivateConnectionAsync(f.Native.Selector, f.Client(),
            f.Scope(lease), default)).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Source.RunListPrivateConnectionsAsync(f.Native.Selector, f.Client(),
            new(new(new(Subscription), "fixture-group"), "foreign-vault"), f.OriginalLimits, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.SelectedReads).IsEqualTo(0);
        await Assert.That((await f.StartInventory(lease)).Complete).IsTrue();
        await Assert.That(async () => await f.StartInventory(lease)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedReads).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task SinglePrivateReadCannotBorrowTheInventoryHook()
    {
        await using var f = new PrivateReadFixture();
        var lease = await f.PrepareAndBaseline();
        await Assert.That(async () => await f.Source.RunListPrivateConnectionsAsync(f.Native.Selector, f.Client(),
            f.Scope(lease).Vault, f.OriginalLimits, default)).Throws<InvalidOperationException>();
        await Assert.That((await f.Start(lease)).Status).IsEqualTo(SecretStatus.Success);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task PrivateInventoryRequiresExplicitAuthoritiesBeforeAnyPreparation()
    {
        await using var f = new PrivateReadFixture(inventory: true);
        await using var source = f.Reopen(omitPrivate: true);
        using var observer = PrivateReadFixture.ObserverFor(source);
        await Assert.That(async () => await observer.PostAsync<Effects.Prepare, Effects.Lease>("vault/prepare",
            f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Wire.Active || f.Endpoint is not null).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PrivateInventoryRestartCannotRecreateOriginalReadiness(bool afterRead)
    {
        await using var f = new PrivateReadFixture(inventory: true);
        var lease = await f.PrepareAndBaseline();
        if (afterRead) await f.StartInventory(lease);
        await using var restarted = f.Reopen();
        await Assert.That(async () => await restarted.RunListPrivateConnectionsAsync(f.Native.Selector, f.Client(),
            f.Scope(lease).Vault, f.OriginalLimits, default)).Throws<InvalidOperationException>();
        using var observer = PrivateReadFixture.ObserverFor(restarted);
        RoleFixtureRelease.Validate(await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedReads).IsEqualTo(afterRead ? 1 : 0);
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
    public async Task PrivateInventoryClosureJoinsEveryActualReadBorrower(string role, string stage, bool dispose)
    {
        await using var f = new PrivateReadFixture(inventory: true);
        var lease = await f.PrepareAndBaseline();
        bool selected = role.StartsWith("selected", StringComparison.Ordinal);
        if (!selected) await f.StartInventory(lease);
        f.Barrier = role + "-" + stage;
        Task borrowed = selected ? f.StartInventory(lease) : f.Observe(lease).AsTask();
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
