using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using D = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalPrivateDeleteRetainsActualOutcomeWithoutInventingPositiveSettlement(string boundary)
    {
        await using var f = new OriginalPrivateUpdateFixture(boundary: boundary, delete: true);
        var result = await f.RunOriginal();
        bool denied = boundary == "denied-authority";
        await Assert.That(result.Passed).IsEqualTo(denied);
        if (!denied) await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SelectedPuts + f.SelectedGets).IsEqualTo(0);
        await Assert.That(f.SetupPuts).IsEqualTo(1);
        await Assert.That(f.CanarySets).IsEqualTo(1);
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
        await Assert.That(f.Endpoint.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(denied ? 1 : 0);
        await Assert.That(f.ParentDeletes).IsEqualTo(denied ? 1 : 0);
        await Assert.That(f.ParentPurges).IsEqualTo(denied ? 1 : 0);
        await Assert.That(f.Native.Read().Released).IsEqualTo(denied);
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(5);
        await Assert.That(f.Prejournaled && f.Native.Wire.Prejournaled).IsTrue();
        if (denied)
        {
            await Assert.That(f.Tap.DeleteStart).IsEqualTo(SecretStatus.Denied);
            await Assert.That(f.Tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Rejected);
            await Assert.That(f.Tap.Completions).IsEqualTo(0);
        }
        else if (boundary is "selected-contract" or "independent-effect")
        {
            await Assert.That(f.Tap.DeleteStart).IsEqualTo(SecretStatus.Success);
            await Assert.That(f.Tap.Completions).IsEqualTo(1);
            await Assert.That(f.Tap.DeleteCompletion).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(f.Tap.DeleteHandle!.State).IsEqualTo(NativeProvisioningState.Pending);
            await Assert.That(f.Tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        }
        if (!denied)
            await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch != Guid.Empty).IsTrue();
    }

    [Test]
    public async Task OriginalPrivateDeleteNativeResourceCompletionSettlesWithOwnedIndependentProof()
    {
        await using var f = new OriginalPrivateUpdateFixture(delete: true);
        f.DeleteResourceBody = true;
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await Assert.That(started.Status).IsEqualTo(SecretStatus.Success);
        await f.Post(lease);
        await Assert.That(await f.Source.CompleteDeletePrivateConnectionAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Success);
        await Assert.That(started.Value!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await f.Release();
        await Assert.That(f.Native.Read().Released && f.Native.Read().Idle).IsTrue();
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SelectedGets + f.SelectedPuts).IsEqualTo(0);
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
        await Assert.That(f.ParentDeletes).IsEqualTo(1);
        await Assert.That(f.ParentPurges).IsEqualTo(1);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    public async Task OriginalPrivateDeletePositiveResourceCasesUseActualOriginalCompletion(string boundary)
    {
        await using var f = new OriginalPrivateUpdateFixture(boundary: boundary, delete: true);
        f.DeleteResourceBody = true;
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(f.Tap.DeleteStart).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Tap.DeleteCompletion).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Tap.Completions).IsEqualTo(1);
        await Assert.That(f.Tap.DeleteHandle!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SelectedGets + f.SelectedPuts).IsEqualTo(0);
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
        await Assert.That(f.ParentDeletes).IsEqualTo(1);
        await Assert.That(f.ParentPurges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released && f.Native.Read().Idle).IsTrue();
    }

    [Test]
    [Arguments("delete-missing-id")]
    [Arguments("delete-foreign-id")]
    [Arguments("delete-foreign-name")]
    [Arguments("delete-foreign-type")]
    [Arguments("delete-foreign-endpoint")]
    [Arguments("delete-state-Pending")]
    [Arguments("delete-state-Approved")]
    [Arguments("delete-state-Rejected")]
    [Arguments("delete-updating")]
    [Arguments("delete-malformed")]
    [Arguments("delete-duplicate")]
    [Arguments("delete-next-link")]
    [Arguments("delete-partial")]
    [Arguments("delete-error")]
    [Arguments("delete-collection")]
    [Arguments("delete-charset")]
    [Arguments("delete-length")]
    [Arguments("delete-continuation")]
    [Arguments("delete-retry")]
    [Arguments("delete-encoding")]
    [Arguments("delete-content-range")]
    [Arguments("delete-status204")]
    public async Task OriginalPrivateDeletePositiveRequiresExactNativeResourceConjunction(string fault)
    {
        await using var f = new OriginalPrivateUpdateFixture(delete: true);
        f.DeleteResourceBody = true;
        f.Fault = fault;
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.FaultsReached > 0).IsTrue();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE") + f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("post-delete-child-present")]
    [Arguments("post-delete-child204")]
    [Arguments("post-delete-child404-malformed")]
    [Arguments("post-delete-child404-forbidden")]
    [Arguments("post-delete-parent-child-present")]
    [Arguments("post-parent-owner")]
    [Arguments("post-parent-configuration")]
    [Arguments("post-endpoint-state")]
    [Arguments("post-endpoint-subnet")]
    [Arguments("post-child-endpoint")]
    [Arguments("canary-digest")]
    [Arguments("canary-version")]
    [Arguments("private-success")]
    [Arguments("public-denied")]
    [Arguments("public-version")]
    [Arguments("public-digest")]
    public async Task OriginalPrivateDeletePositiveNeedsEveryIndependentPostWitness(string fault)
    {
        await using var f = new OriginalPrivateUpdateFixture(delete: true);
        f.DeleteResourceBody = true;
        f.Fault = fault;
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.FaultsReached > 0).IsTrue();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE") + f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalPrivateDeletePositiveResponseReplacementCannotMintDeleted(bool disposeOriginal)
    {
        await using var f = new OriginalPrivateUpdateFixture(delete: true);
        f.DeleteResourceBody = true;
        f.ReplaceResponse = true;
        f.DisposeOriginal = disposeOriginal;
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.Replacements).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE") + f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalPrivateDeleteRestartRequiresDurablePositiveCompletion(bool completed)
    {
        await using var f = new OriginalPrivateUpdateFixture(delete: true);
        f.DeleteResourceBody = true;
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Post(lease);
        if (completed)
            await f.Source.CompleteDeletePrivateConnectionAsync(f.Native.Selector, started.Value!, default);
        await f.RestartRelease();
        await Assert.That(f.Native.Read().Released).IsEqualTo(completed);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SelectedGets + f.SelectedPuts).IsEqualTo(0);
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(completed ? 1 : 0);
        await Assert.That(f.ParentDeletes).IsEqualTo(completed ? 1 : 0);
        await Assert.That(f.ParentPurges).IsEqualTo(completed ? 1 : 0);
    }

    [Test]
    [Arguments("retry")]
    [Arguments("close")]
    [Arguments("dispose")]
    public async Task OriginalPrivateDeletePositiveRetriesOnlyDrainedPairRegistration(string mode)
    {
        await using var f = new OriginalPrivateUpdateFixture(delete: true);
        f.DeleteResourceBody = true;
        var lease = await f.PrepareAndBaseline();
        f.LockOnFinalization = true;
        var started = await f.Start(lease);
        await f.Post(lease);
        await Assert.That(f.JournalLock).IsNull();
        Exception? failure = null;
        try { await f.Source.CompleteDeletePrivateConnectionAsync(f.Native.Selector, started.Value!, default); }
        catch (Exception ex) { failure = ex; }
        try
        {
            await Assert.That(failure).IsNotNull();
            await Assert.That(f.JournalLock).IsNotNull();
        }
        finally { f.UnlockJournal(); }
        int reads = f.PrivateReads + f.PublicReads, requests = f.Endpoint!.Requests.Count;
        if (mode == "retry")
        {
            await Assert.That(await f.Source.CompleteDeletePrivateConnectionAsync(f.Native.Selector, started.Value!, default))
                .IsEqualTo(SecretStatus.Success);
            await Assert.That(f.PrivateReads + f.PublicReads).IsEqualTo(reads);
            await Assert.That(f.Endpoint.Requests.Count).IsEqualTo(requests);
            RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        }
        else
        {
            if (mode == "close") await f.Release();
            await f.Source.DisposeAsync();
            await Assert.That(f.Native.Read().Released || f.Native.Read().Idle).IsFalse();
            await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch != Guid.Empty).IsTrue();
            await Assert.That(f.PrivateReads + f.PublicReads).IsEqualTo(reads);
            await Assert.That(f.Endpoint.Requests.Count).IsEqualTo(requests);
            await Assert.That(f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
        }
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SelectedGets + f.SelectedPuts).IsEqualTo(0);
    }

    [Test]
    public async Task OriginalPrivateDeleteChildResurrectionDuringEndpointCredentialsBlocksCleanup()
    {
        await using var f = new OriginalPrivateUpdateFixture(delete: true);
        f.DeleteResourceBody = true;
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Post(lease);
        await f.Source.CompleteDeletePrivateConnectionAsync(f.Native.Selector, started.Value!, default);
        int credentialCalls = 0;
        f.OnEndpointCredential = () =>
        {
            credentialCalls++;
            f.OnEndpointCredential = null;
            f.Endpoint!.ConnectionPresent = true;
        };
        await f.Release();
        await Assert.That(credentialCalls).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE") + f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
        f.Endpoint.ConnectionPresent = false;
        await f.Release();
        await f.RestartRelease();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Endpoint.Requests.Count(r => r.Method == "DELETE") + f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
    }

    [Test]
    public async Task OriginalPrivateDeleteLostEndpointDeleteResponseCannotReplayAfterDisappearance()
    {
        await using var f = new OriginalPrivateUpdateFixture(delete: true);
        f.DeleteResourceBody = true;
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Post(lease);
        await f.Source.CompleteDeletePrivateConnectionAsync(f.Native.Selector, started.Value!, default);
        int losses = 0;
        f.Endpoint!.BeforeDelete = () =>
        {
            losses++;
            f.Endpoint.BeforeDelete = null;
            f.Endpoint.EndpointExists = f.Endpoint.NicExists = false;
            f.Endpoint.ConnectionPresent = false;
            throw new IOException("controlled-endpoint-delete-response-loss");
        };
        await f.Release();
        await f.Release();
        await f.RestartRelease();
        await Assert.That(losses).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Endpoint.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
        await Assert.That(f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalPrivateDeleteCleanupRejectsForbiddenChild404AtEveryBoundary(bool afterEndpoint)
    {
        await using var f = new OriginalPrivateUpdateFixture(delete: true);
        f.DeleteResourceBody = true;
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Post(lease);
        await f.Source.CompleteDeletePrivateConnectionAsync(f.Native.Selector, started.Value!, default);
        if (afterEndpoint)
            f.Endpoint!.BeforeDelete = () =>
            {
                f.Endpoint.BeforeDelete = null;
                f.Fault = "post-delete-child404-forbidden";
            };
        else f.Fault = "post-delete-child404-forbidden";
        await f.Release();
        await Assert.That(f.FaultsReached > 0).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(afterEndpoint ? 1 : 0);
        await Assert.That(f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
        await f.Release();
        await f.RestartRelease();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Endpoint.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(afterEndpoint ? 1 : 0);
        await Assert.That(f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("denial-child-change")]
    [Arguments("denial-parent-change")]
    [Arguments("denial-malformed")]
    [Arguments("public-version")]
    [Arguments("public-digest")]
    [Arguments("public-denied")]
    public async Task OriginalPrivateDeleteDenialRequiresCompleteUnchangedIndependentEvidence(string fault)
    {
        await using var f = new OriginalPrivateUpdateFixture(boundary: "denied-authority", delete: true);
        f.Fault = fault;
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.FaultsReached > 0).IsTrue();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE") + f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("selected-arm")]
    [Arguments("read-arm")]
    [Arguments("connection-reader-arm")]
    [Arguments("endpoint-reader-arm")]
    [Arguments("private-runtime-secret")]
    [Arguments("public-runtime-secret")]
    public async Task OriginalPrivateDeleteCloseDrainsActualBorrowerBeforeCleanup(string stage)
    {
        await using var f = new OriginalPrivateUpdateFixture(boundary: "denied-authority", delete: true);
        var lease = await f.PrepareAndBaseline();
        Task work;
        if (stage == "selected-arm") { f.Barrier = stage; work = f.Start(lease, denied: true); }
        else { await f.Start(lease, denied: true); f.Barrier = stage; work = f.Post(lease).AsTask(); }
        Task? disposing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await f.Release();
            disposing = f.Source.DisposeAsync().AsTask();
            await Assert.That(work.IsCompleted || disposing.IsCompleted).IsFalse();
            await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE") + f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception ex) when (ex is OperationCanceledException or InvalidOperationException or NativeCaseFailureException) { }
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalPrivateDeleteRejectsIndependentSdkDenialResponseReplacement(bool disposeOriginal)
    {
        await using var f = new OriginalPrivateUpdateFixture(boundary: "denied-authority", delete: true);
        f.ReplaceResponse = true;
        f.DisposeOriginal = disposeOriginal;
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.Replacements).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE") + f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("unresolved")]
    [Arguments("denied")]
    public async Task OriginalPrivateDeleteRestartCannotPromoteObservedAbsenceToSettlement(string state)
    {
        bool denied = state == "denied";
        await using var f = new OriginalPrivateUpdateFixture(boundary: denied ? "denied-authority" : "selected-contract", delete: true);
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease, denied);
        if (denied) await f.Post(lease);
        await f.RestartRelease();
        await Assert.That(f.Native.Read().Released).IsEqualTo(denied);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SelectedGets + f.SelectedPuts).IsEqualTo(0);
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(denied ? 1 : 0);
        await Assert.That(f.ParentDeletes).IsEqualTo(denied ? 1 : 0);
        await Assert.That(f.ParentPurges).IsEqualTo(denied ? 1 : 0);
    }

    [Test]
    [Arguments("retry")]
    [Arguments("close")]
    [Arguments("dispose")]
    public async Task OriginalPrivateDeleteRetriesOnlyDrainedDenialPersistence(string mode)
    {
        await using var f = new OriginalPrivateUpdateFixture(boundary: "denied-authority", delete: true);
        var lease = await f.PrepareAndBaseline();
        f.LockOnFinalization = true;
        await f.Start(lease, denied: true);
        await Assert.That(f.JournalLock).IsNull();
        Exception? failure = null;
        try { await f.Post(lease); }
        catch (Exception ex) { failure = ex; }
        try
        {
            await Assert.That(failure).IsNotNull();
            await Assert.That(f.JournalLock).IsNotNull();
        }
        finally { f.UnlockJournal(); }
        int reads = f.PrivateReads + f.PublicReads, requests = f.Endpoint!.Requests.Count;
        if (mode == "retry")
        {
            await f.Post(lease);
            await Assert.That(f.PrivateReads + f.PublicReads).IsEqualTo(reads);
            await Assert.That(f.Endpoint.Requests.Count).IsEqualTo(requests);
            await Assert.That(f.Native.Read().Idle).IsTrue();
            RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        }
        else
        {
            if (mode == "close") await f.Release();
            await f.Source.DisposeAsync();
            await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
            await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch != Guid.Empty).IsTrue();
            await Assert.That(f.PrivateReads + f.PublicReads).IsEqualTo(reads);
            await Assert.That(f.Endpoint.Requests.Count).IsEqualTo(requests);
            await Assert.That(f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
        }
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SelectedGets + f.SelectedPuts).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalPrivateDeleteUndispatchedReservationSurvivesAllAbsentCleanup(bool restart)
    {
        var time = new PrivateDeleteTimer();
        await using var f = new OriginalPrivateUpdateFixture(delete: true, time: time);
        var lease = await f.PrepareAndBaseline();
        time.Fail = true;
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        time.Fail = false;
        var row = f.Native.Read().PrivateEndpoint!.Connection!;
        await Assert.That(row.ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(row.SelectedAttempted || row.DeleteAttempted).IsFalse();
        await Assert.That(f.SelectedDeletes + f.SelectedCredentialCalls).IsEqualTo(0);
        // Observed disappearance cannot supply a missing invocation certificate.
        f.Native.Wire.Active = f.Native.Wire.Deleted = false;
        f.Endpoint!.EndpointExists = f.Endpoint.NicExists = false;
        f.Endpoint.ConnectionPresent = false;
        if (restart) await f.RestartRelease(); else await f.Release();
        await Assert.That(f.Native.Read().Released || f.Native.Read().Idle).IsFalse();
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(row.ActiveDispatch);
        await Assert.That(f.Endpoint.Requests.Count(r => r.Method == "DELETE") + f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
    }

    private sealed class PrivateDeleteTimer : TimeProvider
    {
        internal bool Fail;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            Fail ? throw new InvalidOperationException("controlled-timer-failure") :
                TimeProvider.System.CreateTimer(callback, state, dueTime, period);
    }

    [Test]
    public async Task OriginalPrivateDeleteRejectsCounterfeitAndGenericSettlement()
    {
        await using var f = new OriginalPrivateUpdateFixture(delete: true);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(() => f.Native.Journal.BeginPrivateConnectionDeleteInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new D.PrivateConnectionDeleteAdmission(f.Source))).Throws<InvalidOperationException>();
        await f.Start(lease);
        var slot = f.Native.Read().PrivateEndpoint!;
        var row = slot.Connection!;
        await Assert.That(row.ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(() => f.Native.Journal.EndPrivateConnectionDeleteInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new D.PrivateConnectionDeleteTermination(f.Source, row.ActiveDispatch))).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettlePrivateConnectionDeleteInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new D.PrivateConnectionDeleteSettlement(f.Source, row.ActiveDispatch))).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndPrivateConnectionApprovalInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, slot.Declaration, row.Id, row.ActiveDispatch)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch, nativeSettled: false))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch)).Throws<InvalidOperationException>();
        f.Native.Journal.Close(Owner, f.Native.Selector);
        await Assert.That(() => f.Native.Journal.RecordAbsence(Owner, f.Native.Selector, row.Id)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(row.ActiveDispatch);
    }
}
